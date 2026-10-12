'use strict';
// One GET fetch per manual submission. No reconnect loop or EventSource.
(() => {
 const LIMIT=512, MAX_TEXT=2048;
 function hostname(value){
  if(typeof value!=='string'||value.length>2048)throw Error('Enter a domain or HTTP(S) URL.');
  value=value.trim();
  if(value.includes('://')){const url=new URL(value);if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error('Only HTTP(S) URLs without credentials are accepted.');value=url.hostname;}
  value=value.replace(/\.$/,'').toLowerCase();
  const labels=value.split('.');
  if(value.length>253||labels.length<2||labels.every(l=>/^\d+$/.test(l))||labels.some(l=>! /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/.test(l))||/(^|\.)(localhost|local|internal|home|lan|test|invalid|onion|in-addr\.arpa|ip6\.arpa|home\.arpa)$/.test(value))throw Error('Enter a public ASCII hostname.');
  return value;
 }
 function bounded(raw){
  if(!raw||typeof raw!=='object'||Array.isArray(raw))throw Error('Invalid stream record.');
  for(const [key,value] of Object.entries(raw)){if(typeof value==='string'&&value.length>MAX_TEXT)throw Error('Stream string exceeds limit.');if(['t_ms','dur_ms','depth','total_ms'].includes(key)&&(typeof value!=='number'||!Number.isFinite(value)||value<0||value>1e7))throw Error('Invalid stream timing.');}
  return raw;
 }
 async function consume(response, signal, record){
  if(!response.ok)throw Error('HTTP '+response.status);
  if(!response.headers.get('content-type')?.startsWith('text/event-stream'))throw Error('Backend did not return SSE.');
  if(!response.body)throw Error('Streaming is unavailable.');
  const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});
  let buffer='',bytes=0,count=0,started=false,terminal=false;
  try{
   while(!terminal){
    if(signal.aborted)throw Error('Cancelled.');
    const {value,done}=await reader.read();
    if(done){buffer+=decoder.decode();if(!terminal)throw Error('Stream interrupted. Use Retry to submit again.');break;}
    bytes+=value.byteLength;if(bytes>1024*1024)throw Error('Stream exceeds limit.');
    buffer+=decoder.decode(value,{stream:true});buffer=buffer.replace(/\r\n/g,'\n');
    let end;
    while((end=buffer.indexOf('\n\n'))>=0){
     const block=buffer.slice(0,end);buffer=buffer.slice(end+2);if(block.length>65536)throw Error('Stream record exceeds limit.');
     let name='',data=[];for(const line of block.split('\n')){if(line.startsWith('event:'))name=line.slice(6).trim();else if(line.startsWith('data:'))data.push(line.slice(5).trimStart());}
     if(!data.length)continue;
     if(terminal)throw Error('Record after terminal.');
     const raw=bounded(JSON.parse(data.join('\n')));
     if(name==='started'){if(started)throw Error('Duplicate started record.');started=true;bounded(raw.question);}
     else if(name==='trace'){if(!started||++count>LIMIT)throw Error('Trace event limit or order violation.');if(!['query_start','query','cname','glueless','cache_hit'].includes(raw.kind))throw Error('Unknown trace event.');}
     else if(name==='done'||name==='error'){if(!started)throw Error('Terminal before started.');terminal=true;if(name==='done'){if(!Array.isArray(raw.answers)||raw.answers.length>64||raw.answers.some(s=>typeof s!=='string'||s.length>MAX_TEXT))throw Error('Invalid answers.');}}
     else throw Error('Unknown stream event.');
     record(name,raw);
    }
    if(buffer.length>65536)throw Error('Stream record exceeds limit.');
   }
  }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
 }
 function init({render,states,generations,validate}){
  const $=id=>document.getElementById(id), input=$('live-name'), submit=$('live-resolve'), retry=$('live-retry'),cancelButton=$('live-cancel'),status=$('live-status');
  let endpoint=null,controller=null,sequence=0;
  function cancel(message='Cancelled.'){sequence++;if(controller){controller.abort();if(states.left?.rcode==='PENDING'){states.left.rcode='INTERRUPTED';render('left',states.left);}}controller=null;cancelButton.disabled=true;submit.disabled=!endpoint;retry.disabled=!endpoint;if(message)status.textContent=message;}
  window.FerroLive={cancel,get active(){return !!controller;}};
  input.addEventListener('input',()=>cancel(endpoint?'Ready.':'Live resolution unavailable: backend is not deployed and verified.'));
  $('live-type').addEventListener('change',()=>cancel(endpoint?'Ready.':'Live resolution unavailable: backend is not deployed and verified.'));
  window.addEventListener('pagehide',()=>cancel(''));
  window.addEventListener('beforeunload',()=>cancel(''));
  cancelButton.addEventListener('click',()=>cancel());
  async function resolve(event){
   event.preventDefault();if(!endpoint)return;
   cancel('');const token=sequence;let name;
   try{name=hostname(input.value);}catch(err){status.textContent=err.message;return;}
   const qtype=$('live-type').value, generation=++generations.left;
   const c=new AbortController();controller=c;submit.disabled=true;retry.disabled=true;cancelButton.disabled=false;status.textContent='Resolving…';
   let live={question:{name,type:qtype},answers:[],events:[],rcode:'PENDING',total_ms:0};states.left=live;render('left',live);
   const timer=setTimeout(()=>c.abort(),18000);
   try{
    const url=new URL('/resolve',endpoint);url.searchParams.set('name',name);url.searchParams.set('type',qtype);
    const response=await fetch(url,{method:'GET',signal:c.signal,credentials:'omit',redirect:'error',cache:'no-store',mode:'cors'});
    await consume(response,c.signal,(kind,raw)=>{
     if(token!==sequence||generation!==generations.left)return;
     if(kind==='started'){status.textContent='Resolving '+name+' '+qtype+'…';}
     if(kind==='trace'){
      if(raw.kind==='query'){const pending=live.events.findIndex(e=>e.kind==='query_start'&&e.ip===raw.ip&&e.qname===raw.qname&&e.qtype===raw.qtype&&e.depth===raw.depth);if(pending>=0)live.events.splice(pending,1);}
      live.events.push(raw);live.total_ms=Math.max(live.total_ms,raw.t_ms+raw.dur_ms);render('left',validate(live));
     }
     if(kind==='done'){live={...raw,events:live.events};states.left=live;render('left',validate(live));status.textContent='Complete · '+raw.rcode;}
     if(kind==='error')throw Error(raw.message||'Resolution failed.');
    });
   }catch(err){if(token===sequence&&generation===generations.left){live.rcode=c.signal.aborted?'INTERRUPTED':'ERROR';states.left=live;render('left',live);status.textContent=c.signal.aborted?'Request cancelled or timed out. Use Retry to submit again.':err.message;}}
   finally{clearTimeout(timer);if(token===sequence){controller=null;submit.disabled=!endpoint;cancelButton.disabled=true;retry.disabled=!endpoint;}}
  }
  $('live-form').addEventListener('submit',resolve);retry.addEventListener('click',resolve);
  fetch('live-config.json',{credentials:'omit',redirect:'error',mode:'same-origin',cache:'no-store'}).then(async response=>{
   if(!response.ok)throw Error('configuration unavailable');const text=await response.text();if(text.length>2048)throw Error('configuration too large');const config=JSON.parse(text);
   if(config.endpoint===null)return;
   const url=new URL(config.endpoint);if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error('invalid endpoint');
   endpoint=url.origin;submit.disabled=false;retry.disabled=false;status.textContent='Ready. Live recursion is experimental and does not validate DNSSEC.';
  }).catch(()=>{status.textContent='Live resolution unavailable: configuration could not be verified.';});
 }
 if(typeof module!=='undefined')module.exports={hostname,bounded,consume};
 else window.FerroLiveInit=init;
})();
