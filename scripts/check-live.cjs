'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {hostname,bounded,consume}=require('../site/viz/live.js');
for(const value of ['example.com','https://example.com/path?q=ignored','A-B.example.com.'])assert.match(hostname(value),/example\.com$/);
for(const value of ['https://user:pass@example.com/','ftp://example.com','localhost','x.internal','x.test','127.1','http://2130706433','http://127.1','http://[::1]','a..com','x_.com','a'.repeat(64)+'.com'])assert.throws(()=>hostname(value),undefined,value);
assert.throws(()=>bounded({detail:'a'.repeat(2049)}));assert.throws(()=>bounded({t_ms:Infinity}));
const encode=new TextEncoder();
const frame=(name,data)=>`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
const started=frame('started',{question:{name:'example.com',type:'A'}}),query=frame('trace',{kind:'query_start',t_ms:0,dur_ms:0,depth:0,qname:'example.com',detail:'<img src=x onerror=alert(1)>'}),done=frame('done',{answers:[],rcode:'NOERROR',total_ms:1,events:[]});
function response(text,split=7){const bytes=encode.encode(text);let offset=0,cancelled=false;return {ok:true,headers:{get:()=> 'text/event-stream'},body:{getReader:()=>({read:async()=>offset>=bytes.length?{done:true}:{done:false,value:bytes.slice(offset,offset+=split)},cancel:async()=>{cancelled=true},releaseLock:()=>{assert(cancelled)}})}};}
class E {constructor(){this.listeners={};this.disabled=true;this.value='example.com';this.textContent='unavailable';}addEventListener(k,f){this.listeners[k]=f;}}
async function lifecycle(){
 const els=new Map(['live-name','live-type','live-resolve','live-retry','live-cancel','live-status','live-form'].map(k=>[k,new E]));els.get('live-type').value='A';
 const listeners={},requests=[],streams=[];
 const window={addEventListener:(k,f)=>listeners[k]=f};
 const context={window,document:{getElementById:k=>els.get(k)},URL,TextDecoder,AbortController,setTimeout,clearTimeout,fetch:async(url,options)=>{
  requests.push({url:String(url),options});if(String(url)==='live-config.json')return {ok:true,text:async()=>JSON.stringify({endpoint:'https://backend.example/'})};
  return await new Promise(resolve=>streams.push({resolve,signal:options.signal}));
 }};
 vm.createContext(context);vm.runInContext(fs.readFileSync('site/viz/live.js','utf8'),context);
 const generations={left:0},states={},renders=[];window.FerroLiveInit({generations,states,validate:x=>x,render:(id,t)=>renders.push(t)});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(els.get('live-resolve').disabled,false);
 const submit=()=>els.get('live-form').listeners.submit({preventDefault(){}});
 const first=submit();assert.equal(requests.length,2);els.get('live-name').listeners.input();assert(streams[0].signal.aborted);assert.equal(els.get('live-retry').disabled,false);
 const second=submit();assert.equal(requests.length,3);
 streams[0].resolve(response(started+query+done));await first;assert.equal(els.get('live-status').textContent,'Resolving…');
 streams[1].resolve(response(started+query+done));await second;assert.equal(els.get('live-status').textContent,'Complete · NOERROR');
 assert(renders.some(t=>t.events.some(e=>e.detail?.startsWith('<img'))));
 const third=submit();window.FerroLive.cancel('File selected.');assert(streams[2].signal.aborted);streams[2].resolve(response(started+done));await third;assert.equal(els.get('live-status').textContent,'File selected.');
 const fourth=submit();listeners.pagehide();assert(streams[3].signal.aborted);streams[3].resolve(response(started+done));await fourth;
 assert.equal(requests.length,5,'one request per explicit submission; no retries');
 for(const request of requests.slice(1)){assert.equal(request.options.method,'GET');assert.equal(request.options.credentials,'omit');assert.equal(new URL(request.url).hostname,'backend.example');}
 // Published null config remains disabled, even if a query parameter offers an override.
 context.fetch=async()=>({ok:true,text:async()=>'{"endpoint":null}'});els.get('live-resolve').disabled=true;els.get('live-retry').disabled=true;
 window.FerroLiveInit({generations,states,validate:x=>x,render:()=>{}});await new Promise(resolve=>setImmediate(resolve));assert.equal(els.get('live-resolve').disabled,true);
}
(async()=>{
 const records=[];await consume(response(started+': heartbeat\n\n'+query+done),new AbortController().signal,(n,r)=>records.push([n,r]));assert.deepEqual(records.map(r=>r[0]),['started','trace','done']);
 for(const text of [started+query,query+done,started+started,started+frame('trace',{kind:'evil'}),started+'event: trace\ndata: '+ 'x'.repeat(65537)+'\n\n',started+frame('done',{answers:['x'.repeat(2049)]}),started+query.repeat(513)+done])await assert.rejects(consume(response(text,1024),new AbortController().signal,()=>{}));
 const c=new AbortController();c.abort();await assert.rejects(consume(response(started+done),c.signal,()=>{}));
 await lifecycle();assert.equal(JSON.parse(fs.readFileSync('site/viz/live-config.json','utf8')).endpoint,null);
 console.log('PASS: live hostname/URL policy, fragmented SSE, bounds/order/terminal/interruption, cancellation, lifecycle races, manual retry, null config (mock DOM)');
})().catch(e=>{console.error(e);process.exitCode=1});
