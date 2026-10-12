'use strict';
// Real Chromium DOM verification, isolated profile and temporary served config.
// Default: mocked DNS. --actual-backend URL or --run-backend: two paced public queries.
// Actual mode: loopback page + streaming same-origin relay, test-only served JS override.
// HTTPS config validation and published CORS/config remain unchanged; owner proof required.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
const profile=fs.mkdtempSync(path.join(os.tmpdir(),'ferrodns-browser-'));
const chromePath=process.env.FERRODNS_CHROME|| (process.platform==='darwin'?'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome':'chromium');
const origin='https://tczartoryski.github.io';let chrome,server,ws,backend;
const args=process.argv.slice(2);let actual=null;
if(args[0]==='--run-backend'&&args.length===1)actual='http://127.0.0.1:8080';
else if(args[0]==='--actual-backend'&&args.length===2)actual=args[1];
else if(args.length)throw Error('Usage: node scripts/check-live-browser.cjs [--run-backend | --actual-backend http://127.0.0.1:PORT]');
if(actual){const url=new URL(actual);assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,'/');assert(!url.search&&!url.hash&&!url.username&&!url.password);actual=url.origin;}
async function stop(child){if(!child?.pid||child.exitCode!==null||child.signalCode!==null)return;const exited=new Promise(r=>child.once('close',r));if(child===backend)process.kill(-child.pid,'SIGTERM');else child.kill();await exited;}

const delay=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 let enabled=false,mode='success',queries=0,actualMode=false,actualQueries=0,lastActualQuery=0;
 if(args[0]==='--run-backend'){
  backend=spawn(process.env.CARGO||'cargo',['run','--bin','ferrodns-live','--','--bind','127.0.0.1:8080'],{stdio:['ignore','ignore','pipe'],detached:true});
  let output='';backend.stderr.on('data',b=>output+=b);backend.on('error',e=>output+=e.message);
  let ready=false;for(let i=0;i<600;i++){if(output.includes('live HTTP listening on 127.0.0.1:8080')){ready=true;break;}if(backend.exitCode!==null||!backend.pid)throw Error('Backend failed: '+output);await delay(100);}assert(ready,'Backend startup timeout: '+output);
 }

 server=http.createServer((req,res)=>{
  const requestURL=new URL(req.url,'http://localhost');
  if(requestURL.pathname==='/resolve'){
   // The actual loopback page uses this test-only relay. Supply the
   // explicit Pages Origin; never replay, retry, or collect the SSE body.
   const name=['example.com','www.apple.com'][actualQueries];
   if(!actualMode||req.method!=='GET'||
      requestURL.searchParams.get('name')!==name||requestURL.searchParams.get('type')!=='A'||
      [...requestURL.searchParams.keys()].join(',')!=='name,type'||
      (actualQueries&&Date.now()-lastActualQuery<12000)){
    res.writeHead(400);return res.end('Unexpected actual query');
   }
   actualQueries++;lastActualQuery=Date.now();
   const upstream=http.get(actual+requestURL.pathname+requestURL.search,{headers:{Origin:origin}},response=>{
    res.writeHead(response.statusCode, response.headers);res.flushHeaders();
    response.on('error',error=>res.destroy(error));
    response.pipe(res); // Native backpressure; each arriving chunk goes to Chromium.
   });
   upstream.on('error',error=>{console.error('Relay: '+error.message);res.destroy(error);});
   res.on('close',()=>upstream.destroy());
   return;
  }
  if(req.url==='/viz/live-config.json'){res.setHeader('Content-Type','application/json');const file=path.join(profile,'live-config.json');fs.writeFileSync(file,JSON.stringify({endpoint:enabled?'https://temporary.backend.example/':null}));return res.end(fs.readFileSync(file,'utf8'));}
  const relative=new URL(req.url,'http://localhost').pathname.slice(1);if(!/^viz\/(index\.html|live\.js|samples\/[a-z-]+\.json)$/.test(relative)){res.statusCode=404;return res.end();}
  res.setHeader('Content-Type',relative.endsWith('.html')?'text/html':relative.endsWith('.js')?'application/javascript':'application/json');let body=fs.readFileSync(path.join('site',relative),'utf8');
  if(actualMode&&relative==='viz/live.js'){
   // Change only the request destination in this served copy, after the original
   // HTTPS-only config validation. The repository's live.js is never written.
   const source="const url=new URL('/resolve',endpoint);";
   assert.equal(body.split(source).length,2,'Exactly one test fetch destination');
   body=body.replace(source,"const url=new URL('/resolve',location.origin);");
  }
  res.end(body);
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
 const local=`http://127.0.0.1:${server.address().port}`;const base=origin+'/ferrodns/viz/';
 chrome=spawn(chromePath,['--headless=new','--disable-gpu','--disable-background-networking','--disable-component-update','--disable-sync','--metrics-recording-only','--no-first-run','--no-default-browser-check',`--user-data-dir=${profile}`,'--remote-debugging-port=0','about:blank'],{stdio:['ignore','ignore','pipe']});
 let stderr='';chrome.stderr.on('data',b=>stderr+=b);chrome.on('error',()=>{});
 let debug;for(let i=0;i<100;i++){const match=stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match){debug=match[1];break;}if(chrome.exitCode!==null)throw Error('Chrome exited: '+stderr.slice(-500));await delay(50);}if(!debug)throw Error('Chrome DevTools unavailable');
 const port=new URL(debug).port;const pages=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let next=0;const pending=new Map();const errors=[];const networkRequests=new Map();
 const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++next;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
 ws.onmessage=({data})=>{void onMessage(data).catch(e=>{errors.push(e.stack||e.message);});};
 const onMessage=async data=>{const msg=JSON.parse(data);if(msg.id){const p=pending.get(msg.id);pending.delete(msg.id);msg.error?p.reject(Error(JSON.stringify(msg.error))):p.resolve(msg.result);}
  else if(msg.method==='Network.requestWillBeSent')networkRequests.set(msg.params.requestId,msg.params.request.url);
  else if(msg.method==='Network.loadingFinished')networkRequests.delete(msg.params.requestId);
  else if(msg.method==='Network.loadingFailed'){
   console.error('Network.loadingFailed '+JSON.stringify({...msg.params,url:networkRequests.get(msg.params.requestId)}));
   networkRequests.delete(msg.params.requestId);
  }
  else if(msg.method==='Runtime.exceptionThrown')errors.push(msg.params.exceptionDetails.text);
  else if(msg.method==='Fetch.requestPaused'){
   const {requestId,request}=msg.params;
   if(request.url.startsWith(origin+'/ferrodns/')){const url=new URL(request.url);const response=await fetch(local+url.pathname.replace('/ferrodns/','/')+url.search);await call('Fetch.fulfillRequest',{requestId,responseCode:response.status,responseHeaders:[{name:'Content-Type',value:response.headers.get('content-type')||'text/plain'}],body:Buffer.from(await response.arrayBuffer()).toString('base64')});return;}
   assert.equal(new URL(request.url).hostname,'temporary.backend.example');assert.equal(request.headers.Origin,origin);
   assert(!actualMode,'Actual SSE must use the loopback streaming relay');
   queries++;
   const trace={question:{name:'example.com',type:'A'},total_ms:1,rcode:'NOERROR',answers:['example.com. 30 IN A 8.8.8.8'],events:[]};
   const text=`event: started\ndata: ${JSON.stringify({question:trace.question})}\n\nevent: trace\ndata: ${JSON.stringify({kind:'query_start',t_ms:0,dur_ms:0,depth:0,qname:'example.com',qtype:'A',ip:'8.8.8.8',detail:'<img src=x onerror=alert(1)>'})}\n\n`+(mode==='success'?`event: done\ndata: ${JSON.stringify(trace)}\n\n`:'');
   await call('Fetch.fulfillRequest',{requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'text/event-stream'},{name:'Access-Control-Allow-Origin',value:origin}],body:Buffer.from(text).toString('base64')});
  }
 };
 const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.text);return r.result.value};
 const until=async expression=>{for(let i=0;i<100;i++){assert.deepEqual(errors,[]);if(await evaluate(expression))return;await delay(25);}throw Error('Browser condition timed out: '+expression);};
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
 if(actual){
  actualMode=true;
  // Same-origin loopback browser requests need no synthetic Origin; the relay
  // supplies the Pages Origin only on its actual backend request.
  await call('Network.setExtraHTTPHeaders',{headers:{}});
  const cases=[{width:1280,height:900,mobile:false,name:'example.com'},{width:390,height:844,mobile:true,name:'www.apple.com'}];
  for(const [i,test] of cases.entries()){
   if(i)await delay(12000);
   await call('Emulation.setDeviceMetricsOverride',{width:test.width,height:test.height,deviceScaleFactor:test.mobile?3:1,mobile:test.mobile});
   await navigate(local+'/viz/index.html');await until("!document.getElementById('live-resolve').disabled");
   await evaluate(`window.liveEvidence={submitted:performance.now(),submitted_at:new Date().toISOString(),first:null,final:null,pending:false};window.liveObserver=new MutationObserver(()=>{const e=window.liveEvidence;if(document.querySelector('#left .row.active')&&document.getElementById('live-status').textContent.startsWith('Resolving')){if(e.first===null)e.first=performance.now();e.pending=true;}if(document.getElementById('live-status').textContent==='Complete · NOERROR'&&e.final===null)e.final=performance.now();});window.liveObserver.observe(document.body,{subtree:true,childList:true});document.getElementById('live-name').value=${JSON.stringify(test.name)};document.getElementById('live-form').requestSubmit()`);
   // Allow the frontend's full 18s deadline; never retry a failed public query.
   for(let n=0;n<800;n++){assert.deepEqual(errors,[]);if(await evaluate("window.liveEvidence.final!==null || document.getElementById('live-status').textContent.includes('Retry') || document.getElementById('live-status').textContent==='Resolution failed.'"))break;await delay(25);}
   const evidence=await evaluate("({...window.liveEvidence,status:document.getElementById('live-status').textContent,answers:document.querySelector('#left .answers')?.textContent,overflow:document.documentElement.scrollWidth>innerWidth})");
   assert.equal(evidence.status,'Complete · NOERROR');assert(evidence.pending&&evidence.first<evidence.final,'Live pending DOM must precede terminal DOM');assert(evidence.answers,'Real answers rendered');assert(!evidence.overflow,'Viewport overflow');
   console.log(JSON.stringify({viewport:test.mobile?'mobile':'desktop',name:test.name,submitted_at:evidence.submitted_at,first_ms:evidence.first-evidence.submitted,final_ms:evidence.final-evidence.submitted,answers:evidence.answers}));
   await evaluate('window.liveObserver.disconnect()');
  }
  assert.equal(actualQueries,2);assert.deepEqual(errors,[]);console.log('PASS: actual loopback ferrodns incremental SSE, desktop and mobile, two public queries 12s apart');
 }

})().catch(e=>{console.error(e.message);process.exitCode=1}).finally(async()=>{
 ws?.close();await stop(chrome);await stop(backend);
 if(server?.listening)await new Promise(r=>server.close(r));
 await fs.promises.rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100});
}).catch(e=>{console.error('Cleanup: '+e.message);process.exitCode=1});
