
const json=(v,s=200)=>new Response(JSON.stringify(v),{status:s,headers:{"content-type":"application/json","cache-control":"no-store"}});
const html=(s)=>new Response(s,{headers:{"content-type":"text/html;charset=utf-8","cache-control":"no-store","content-security-policy":"default-src 'none';style-src 'unsafe-inline';form-action 'self';frame-ancestors 'none'"}});
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const hex=n=>[...crypto.getRandomValues(new Uint8Array(n))].map(x=>x.toString(16).padStart(2,"0")).join("");
const hash=async s=>[...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s)))].map(x=>x.toString(16).padStart(2,"0")).join("");
async function read(req){const s=await req.text();if(s.length>131072)throw Error("Body too large");return req.headers.get("content-type")?.includes("form-urlencoded")?Object.fromEntries(new URLSearchParams(s)):JSON.parse(s||"{}");}
export default {async fetch(req,env){
 const u=new URL(req.url),h=u.hostname,p=u.pathname,worker=h==="private-desktop-device-relay.ljx2043979076.workers.dev",owner=h==="mcp.qqking.top"||(worker&&(["/mcp","/admin/devices","/admin/approve","/admin/select","/admin/revoke"].includes(p))),relay=h==="relay.qqking.top"||(worker&&(["/relay/status","/relay/pair/start","/relay/pair/poll","/relay/ws","/relay/diagnostic"].includes(p)));
 if(!owner&&!relay)return new Response("No route",{status:404});
 if(owner){
  if(!["/admin/devices","/admin/approve","/admin/select","/admin/revoke","/mcp"].includes(p))return new Response("No route",{status:404});
  if(!req.headers.get("cf-access-jwt-assertion"))return new Response("Cloudflare Access required",{status:403});
  if(p.startsWith("/admin/")&&req.method==="POST"){
   const o=req.headers.get("origin");if(!o||new URL(o).hostname!==h)return new Response("Origin rejected",{status:403});
  }
 }else if(!["/relay/status","/relay/pair/start","/relay/pair/poll","/relay/ws","/relay/diagnostic"].includes(p))return new Response("No route",{status:404});
 return env.HUB.getByName("owner-main").fetch(req);
}};
export class DeviceHub{
 constructor(ctx,env){this.ctx=ctx;this.env=env;this.inflight=new Map();}
 open(){const found=new Map();for(const w of this.ctx.getWebSockets()){const a=w.deserializeAttachment();if(a?.deviceId&&w.readyState===WebSocket.OPEN)found.set(a.deviceId,w);}return found;}
 async list(){const r=await this.ctx.storage.list({prefix:"device:"}),w=this.open();return [...r.values()].map(d=>({id:d.id,name:d.name,approvedAt:d.approvedAt,online:w.has(d.id)}));}
 async fetch(req){
 const p=new URL(req.url).pathname,m=req.method;
 try{
  if(p==="/relay/status"&&m==="GET")return json({ok:true,version:"0.1"});
  if(p==="/relay/pair/start"&&m==="POST")return this.pairStart(req);
  if(p==="/relay/pair/poll"&&m==="POST")return this.pairPoll(req);
  if(p==="/relay/ws"&&m==="GET")return this.connect(req);
  if(p==="/relay/diagnostic"&&m==="POST")return this.diagnostic(req);
  if(p==="/admin/devices"&&m==="GET")return this.dashboard();
  if(p==="/admin/approve"&&m==="POST")return this.approve(req);
  if(p==="/admin/select"&&m==="POST")return this.select(req);
  if(p==="/admin/revoke"&&m==="POST")return this.revoke(req);
  if(p==="/mcp"&&m==="POST")return this.proxy(req);
  if(p==="/mcp"&&m==="GET")return new Response("POST only",{status:405,headers:{"allow":"POST"}});
  return new Response("Not found",{status:404});
 }catch(e){return json({error:String(e.message||e).slice(0,180)},500);}
 }
 async pairStart(req){
  const d=await read(req),name=String(d.name||"Windows").replace(/[^a-zA-Z0-9_. -]/g,"").slice(0,40)||"Windows";
  const ip=req.headers.get("cf-connecting-ip")||"unknown",key="rate:"+ip;
  let limit=await this.ctx.storage.get(key)||{n:0,until:0};
  if(Date.now()>limit.until)limit={n:0,until:Date.now()+300000};
  if(++limit.n>5)return json({error:"Pairing rate limit"},429);
  await this.ctx.storage.put(key,limit,{expirationTtl:360});
  const pending=await this.ctx.storage.list({prefix:"pending:"});
  for(const [key,request] of pending){if(request.expires<Date.now()){await this.ctx.storage.delete(key);pending.delete(key);}}
  if(pending.size>20)return json({error:"Too many pending devices"},429);
  const id=crypto.randomUUID(),proof=hex(32),code=hex(5).toUpperCase();
  await this.ctx.storage.put("pending:"+id,{id,proof,code,name,expires:Date.now()+3600000,approved:false},{expirationTtl:4200});
  return json({pairId:id,proof,code,approvalUrl:new URL(req.url).hostname.endsWith(".workers.dev")?"https://private-desktop-device-relay.ljx2043979076.workers.dev/admin/devices":"https://mcp.qqking.top/admin/devices",expiresIn:3600});
 }
 async pairPoll(req){
  const {pairId,proof}=await read(req),r=await this.ctx.storage.get("pending:"+String(pairId||""));
  if(!r||r.proof!==proof||r.expires<Date.now())return json({error:"Pairing expired"},404);
  if(!r.approved)return json({status:"pending"});
  await this.ctx.storage.delete("pending:"+r.id);
  return json({status:"approved",deviceId:r.deviceId,token:r.token});
 }
 async connect(req){
  if(req.headers.get("upgrade")?.toLowerCase()!=="websocket")return new Response("WebSocket required",{status:426});
  const id=req.headers.get("x-device-id")||"",a=req.headers.get("authorization")||"";
  if(!/^Bearer [a-f0-9]{64}$/.test(a))return new Response("Unauthorized",{status:401});
  const d=await this.ctx.storage.get("device:"+id);
  if(!d||d.hash!==await hash(a.slice(7)))return new Response("Unauthorized",{status:401});
  for(const w of this.ctx.getWebSockets()){if(w.deserializeAttachment()?.deviceId===id){try{w.close(1000,"Reconnected")}catch{}}}
  const pair=new WebSocketPair(),[client,server]=Object.values(pair);
  this.ctx.acceptWebSocket(server);server.serializeAttachment({deviceId:id});
  return new Response(null,{status:101,webSocket:client});
 }
 async dashboard(){
  const pending=await this.ctx.storage.list({prefix:"pending:"}),devices=await this.list(),selected=await this.ctx.storage.get("selected");
  const form=(act,id,label)=>'<form action="/admin/'+act+'" method="post"><input type="hidden" name="id" value="'+esc(id)+'"><button>'+esc(label)+'</button></form>';
  const p=[...pending.values()].filter(x=>!x.approved&&x.expires>Date.now()).map(x=>'<li>'+esc(x.name)+' — 配对码 <b>'+esc(x.code)+'</b> '+form("approve",x.id,"批准设备")+'</li>').join("")||"<li>暂无待批准的设备</li>";
  const d=devices.map(x=>'<li>'+esc(x.name)+' — '+(x.online?"在线":"离线")+' '+(selected===x.id?"(当前选中)":"")+form("select",x.id,"选择此设备")+form("revoke",x.id,"撤销授权")+'</li>').join("")||"<li>暂无设备</li>";
  return html('<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Private Desktop MCP</title><style>body{font:16px system-ui;max-width:780px;margin:2rem auto;padding:1rem;background:#fafafa}li{margin:1rem 0;padding:1rem;background:white;border-radius:12px}form{display:inline;margin:0 .3rem}button{padding:.4rem}</style><h1>Private Desktop MCP 设备管理</h1><p>此页面由 Cloudflare Access 登录保护。</p><h2>待批准</h2><ul>'+p+'</ul><h2>已配对</h2><ul>'+d+'</ul><a href="/admin/devices">刷新</a></html>');
 }
 async approve(req){const {id}=await read(req),key="pending:"+id,p=await this.ctx.storage.get(key);
  if(!p||p.expires<Date.now()||p.approved)return new Response("Expired",{status:400});
  const deviceId=crypto.randomUUID(),token=hex(32);
  await this.ctx.storage.put("device:"+deviceId,{id:deviceId,name:p.name,hash:await hash(token),approvedAt:new Date().toISOString()});
  await this.ctx.storage.put(key,{...p,approved:true,deviceId,token,expires:Date.now()+600000},{expirationTtl:600});
  return Response.redirect(new URL("/admin/devices",req.url).href,303);
 }
 async select(req){const {id}=await read(req);if(!await this.ctx.storage.get("device:"+id))return new Response("Unknown",{status:404});
  await this.ctx.storage.put("selected",id);return Response.redirect(new URL("/admin/devices",req.url).href,303);
 }
 async revoke(req){const {id}=await read(req);await this.ctx.storage.delete("device:"+id);
  if(await this.ctx.storage.get("selected")===id)await this.ctx.storage.delete("selected");
  for(const w of this.ctx.getWebSockets()){if(w.deserializeAttachment()?.deviceId===id){try{w.close(1008,"Revoked")}catch{}}}
  return Response.redirect(new URL("/admin/devices",req.url).href,303);
 }
 async diagnostic(req){
  const id=req.headers.get("x-device-id")||"",authorization=req.headers.get("authorization")||"";
  if(!/^Bearer [a-f0-9]{64}$/.test(authorization))return json({error:"Unauthorized"},401);
  const device=await this.ctx.storage.get("device:"+id);
  if(!device||device.hash!==await hash(authorization.slice(7)))return json({error:"Unauthorized"},401);
  const body=await req.text();if(body.length>8192)return json({error:"Body too large"},413);
  let msg;try{msg=JSON.parse(body)}catch{return json({error:"Invalid JSON"},400)}
  if(msg.jsonrpc!=="2.0"||!["initialize","notifications/initialized","tools/list","tools/call"].includes(msg.method))return json({error:"Method denied"},403);
  if(msg.method==="tools/call"&&(msg.params?.name!=="read_file"||msg.params?.arguments?.path!=="C:\\workspace\\private-desktop-device-relay\\package.json"||Number(msg.params?.arguments?.length||10)>10))return json({error:"Unsafe diagnostic call"},403);
  const h=new Headers({"content-type":"application/json","accept":"application/json, text/event-stream"});
  for(const k of ["mcp-session-id","mcp-protocol-version"])if(req.headers.has(k))h.set(k,req.headers.get(k));
  return this.proxy(new Request("https://private-desktop-device-relay.ljx2043979076.workers.dev/mcp",{method:"POST",headers:h,body}),id);
 }
 async proxy(req,forcedId=null){
  const online=this.open(),selected=await this.ctx.storage.get("selected");
  let id=forcedId||selected;
  if(!forcedId&&id&&!online.has(id)&&online.size===1)id=online.keys().next().value;
  if(id&&!online.has(id))return json({error:"Selected device offline"},503);
  if(!id){if(!online.size)return json({error:"No device online"},503);
   if(online.size>1)return json({error:"Multiple devices online; select at /admin/devices"},409);
   id=online.keys().next().value;}
  const ws=online.get(id),body=await req.text();if(body.length>1048576)return new Response("Too large",{status:413});
  const headers={};for(const k of ["accept","content-type","mcp-session-id","mcp-protocol-version","last-event-id","mcp-method","mcp-name"])if(req.headers.get(k))headers[k]=req.headers.get(k);
  const requestId=crypto.randomUUID();
  const res=await new Promise(resolve=>{
   const timer=setTimeout(()=>{this.inflight.delete(requestId);resolve({status:504,headers:{"content-type":"application/json"},body:'{"error":"Timeout"}'})},75000);
   this.inflight.set(requestId,{ws,resolve:v=>{clearTimeout(timer);resolve(v)}});
   try{ws.send(JSON.stringify({kind:"request",id:requestId,method:"POST",headers,body}));}
   catch(e){clearTimeout(timer);this.inflight.delete(requestId);resolve({status:503,body:'{"error":"Disconnected"}',headers:{"content-type":"application/json"}})}
  });
  const h=new Headers({"cache-control":"no-store"});for(const key of ["content-type","mcp-session-id","mcp-protocol-version"])if(res.headers?.[key])h.set(key,res.headers[key]);
  return new Response([202,204].includes(res.status)?null:String(res.body||""),{status:res.status||502,headers:h});
 }
 async webSocketMessage(ws,message){let d;try{d=JSON.parse(String(message))}catch{return}
  const slot=d?.id&&this.inflight.get(d.id);
  if(d.kind==="response"&&slot&&slot.ws===ws){this.inflight.delete(d.id);slot.resolve({status:Number(d.status)||500,headers:d.headers||{},body:String(d.body||"")});}
 }
 async webSocketClose(ws){for(const [id,p] of this.inflight){if(p.ws===ws){this.inflight.delete(id);p.resolve({status:503,headers:{"content-type":"application/json"},body:'{"error":"Device disconnected"}'})}}}
 async webSocketError(ws){return this.webSocketClose(ws)}
}
