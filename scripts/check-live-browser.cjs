'use strict';
// Real Chromium DOM verification, isolated profile and temporary served config.
// No dependencies, external DNS, screenshots, or published config changes.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
const profile=fs.mkdtempSync(path.join(os.tmpdir(),'ferrodns-browser-'));
const chromePath=process.env.FERRODNS_CHROME|| (process.platform==='darwin'?'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome':'chromium');
const origin='https://tczartoryski.github.io';let chrome,server,ws;
const delay=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 let enabled=false,mode='success',queries=0;
 server=http.createServer((req,res)=>{
  if(req.url==='/viz/live-config.json'){res.setHeader('Content-Type','application/json');const file=path.join(profile,'live-config.json');fs.writeFileSync(file,JSON.stringify({endpoint:enabled?'https://temporary.backend.example/':null}));return res.end(fs.readFileSync(file,'utf8'));}
  const relative=new URL(req.url,'http://localhost').pathname.slice(1);if(!/^viz\/(index\.html|live\.js|samples\/[a-z-]+\.json)$/.test(relative)){res.statusCode=404;return res.end();}
  res.setHeader('Content-Type',relative.endsWith('.html')?'text/html':relative.endsWith('.js')?'application/javascript':'application/json');res.end(fs.readFileSync(path.join('site',relative)));
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
 const local=`http://127.0.0.1:${server.address().port}`;const base=origin+'/ferrodns/viz/';
 chrome=spawn(chromePath,['--headless=new','--disable-gpu','--disable-background-networking','--disable-component-update','--disable-sync','--metrics-recording-only','--no-first-run','--no-default-browser-check',`--user-data-dir=${profile}`,'--remote-debugging-port=0','about:blank'],{stdio:['ignore','ignore','pipe']});
 let stderr='';chrome.stderr.on('data',b=>stderr+=b);chrome.on('error',()=>{});
 let debug;for(let i=0;i<100;i++){const match=stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match){debug=match[1];break;}if(chrome.exitCode!==null)throw Error('Chrome exited: '+stderr.slice(-500));await delay(50);}if(!debug)throw Error('Chrome DevTools unavailable');
 const port=new URL(debug).port;const pages=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let next=0;const pending=new Map();const errors=[];
 const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++next;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
 ws.onmessage=async({data})=>{const msg=JSON.parse(data);if(msg.id){const p=pending.get(msg.id);pending.delete(msg.id);msg.error?p.reject(Error(JSON.stringify(msg.error))):p.resolve(msg.result);}
  else if(msg.method==='Runtime.exceptionThrown')errors.push(msg.params.exceptionDetails.text);
  else if(msg.method==='Fetch.requestPaused'){
   const {requestId,request}=msg.params;
   if(request.url.startsWith(origin+'/ferrodns/')){const url=new URL(request.url);const response=await fetch(local+url.pathname.replace('/ferrodns/','/')+url.search);await call('Fetch.fulfillRequest',{requestId,responseCode:response.status,responseHeaders:[{name:'Content-Type',value:response.headers.get('content-type')||'text/plain'}],body:Buffer.from(await response.arrayBuffer()).toString('base64')});return;}
   assert.equal(new URL(request.url).hostname,'temporary.backend.example');assert.equal(request.headers.Origin,origin);queries++;
   const trace={question:{name:'example.com',type:'A'},total_ms:1,rcode:'NOERROR',answers:['example.com. 30 IN A 8.8.8.8'],events:[]};
   const text=`event: started\ndata: ${JSON.stringify({question:trace.question})}\n\nevent: trace\ndata: ${JSON.stringify({kind:'query_start',t_ms:0,dur_ms:0,depth:0,qname:'example.com',qtype:'A',ip:'8.8.8.8',detail:'<img src=x onerror=alert(1)>'})}\n\n`+(mode==='success'?`event: done\ndata: ${JSON.stringify(trace)}\n\n`:'');
   await call('Fetch.fulfillRequest',{requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'text/event-stream'},{name:'Access-Control-Allow-Origin',value:origin}],body:Buffer.from(text).toString('base64')});
  }
 };
 const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.text);return r.result.value};
 const until=async expression=>{for(let i=0;i<100;i++){if(await evaluate(expression))return;await delay(25);}throw Error('Browser condition timed out: '+expression);};
 await call('Runtime.enable');await call('Network.enable');await call('Network.setExtraHTTPHeaders',{headers:{Origin:origin}});
 await call('Fetch.enable',{patterns:[{urlPattern:origin+'/ferrodns/*'},{urlPattern:'https://temporary.backend.example/*'}]});
 await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:3,mobile:true});
 const navigate=async url=>{await call('Page.navigate',{url});await until("document.readyState==='complete'");await delay(100);};
 await navigate(base+'index.html?endpoint=https://evil.example');assert(await evaluate("document.getElementById('live-resolve').disabled && document.getElementById('live-status').textContent.includes('unavailable')"));
 enabled=true;await navigate(base+'index.html');await until("!document.getElementById('live-resolve').disabled");
 await evaluate("document.getElementById('live-name').value='https://example.com/path';document.getElementById('live-form').requestSubmit()");await until("document.getElementById('live-status').textContent==='Complete · NOERROR'");assert(await evaluate("document.querySelectorAll('#left img').length===0 && document.querySelector('#left .row.active')===null"));
 mode='interrupted';await evaluate("document.getElementById('live-form').requestSubmit()");await until("document.getElementById('live-status').textContent.includes('interrupted')");await delay(200);assert.equal(queries,2,'no automatic retry');
 for(const sample of ['apple-cold','apple-warm','nxdomain','google-txt','simulated-tcp']){await navigate(base+'index.html?trace=samples/'+sample+'.json');await until("document.querySelector('#left svg')!==null");assert(await evaluate("!document.querySelector('#left .error') && document.documentElement.scrollWidth<=innerWidth"),sample);}
 assert.deepEqual(errors,[]);console.log('PASS: real Chromium mobile 390px, null endpoint, explicit Origin, live text-only UI, interruption/no retry, five samples');
})().catch(e=>{console.error(e.message);process.exitCode=1}).finally(()=>{ws?.close();chrome?.kill();server?.close();fs.rmSync(profile,{recursive:true,force:true});});
