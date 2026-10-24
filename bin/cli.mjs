#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {spawn,spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import WebSocket from "ws";
import { ProxyAgent } from "undici";
import { resolveProxyForUrl } from "./proxy.mjs";
import { HttpsProxyAgent } from "https-proxy-agent";
import { logLine, sanitizeText } from "./logging.mjs";
import { callInfo, requestBrief, requestDebug, responseBrief, safeTraceRequest, safeTraceOutput, shortCallId, formatElapsed, loggingOptions } from "./activity.mjs";

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const command=process.argv.slice(2).find(a=>!a.startsWith("--"))||"connect",relay="https://private-desktop-device-relay.ljx2043979076.workers.dev";
const {trace,debug}=loggingOptions(process.argv.slice(2));
const config=path.join(process.env.APPDATA||path.join(os.homedir(),".config"),"PrivateDesktopMCP","device.json");
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let currentProxy=null,proxyCheckedAt=0,lastProxyNotice="";
const agents=new Map();
function remoteTransport(){
 if(!currentProxy||Date.now()-proxyCheckedAt>10000){
  currentProxy=resolveProxyForUrl(relay);
  proxyCheckedAt=Date.now();
  if(currentProxy.mode==="unsupported")throw Error(currentProxy.reason+" (use an HTTP/Mixed port via system settings or HTTPS_PROXY)");
  const notice=currentProxy.mode==="proxy"?"🌐 Proxy: "+currentProxy.source+" ("+currentProxy.description+")":
   currentProxy.mode==="unavailable"?"⚠️ Proxy detection unavailable: "+currentProxy.reason+"; trying direct":
   "🌐 Direct connection ("+currentProxy.source+")";
  if(notice!==lastProxyNotice){logLine(currentProxy.mode==="unavailable"?"warn":"info",notice);lastProxyNotice=notice}
 }
 if(currentProxy.mode!=="proxy")return {};
 let transport=agents.get(currentProxy.url);
 if(!transport){
  transport={dispatcher:new ProxyAgent(currentProxy.url),wsAgent:new HttpsProxyAgent(currentProxy.url)};
  agents.set(currentProxy.url,transport);
 }
 return transport;
}
let stopping=false,child=null,socket=null;
let connectionAttempt=0,connectedSince=0,sessionCalls=0,sessionFails=0,allCalls=0,allFails=0,lastError="";
function reportDevice(creds){
 logLine("info","━━━━━━━━━━━━━━━━ PCC DEVICE READY ━━━━━━━━━━━━━━━━");
 logLine("info","Computer: "+os.hostname()+" | User: "+os.userInfo().username+" | Node: "+process.version);
 logLine("info","Device ID: "+creds.deviceId+" | Gateway PID: "+(child?.pid||"unknown"));
 logLine("info","Relay: "+relay+" | Local MCP: http://127.0.0.1:8717/mcp");
 logLine("info","Mode: "+(trace?"TRACE":debug?"DEBUG":"LIVE"));
 logLine("info","Return to ChatGPT; keep this terminal running. Ctrl+C to disconnect.");
 logLine("info","━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
function saved(){try{return JSON.parse(fs.readFileSync(config,"utf8"))}catch{return null}}
function store(x){fs.mkdirSync(path.dirname(config),{recursive:true,mode:0o700});fs.writeFileSync(config,JSON.stringify(x,null,2),{mode:0o600});}
function forget(){try{fs.unlinkSync(config)}catch{}}
async function post(route,data){const {dispatcher}=remoteTransport();const r=await fetch(relay+route,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(data),signal:AbortSignal.timeout(12000),...(dispatcher?{dispatcher}:{})});const j=await r.json();if(!r.ok)throw Error(j.error||"HTTP "+r.status);return j;}
async function pair(){
 const v=await post("/relay/pair/start",{name:os.hostname()});
 logLine("info","🔑 New device pairing requested");
 console.log("\nNEW DEVICE: "+os.hostname()+"\nPAIRING CODE: "+v.code+"\nPlease visit "+v.approvalUrl+" and approve the matching code.\nWaiting for approval (60 minutes)...\n");
 for(let i=0;i<720&&!stopping;i++){
  await sleep(5000);let r;try{r=await post("/relay/pair/poll",{pairId:v.pairId,proof:v.proof})}catch(e){if(/expired|invalid/i.test(e.message))throw e;continue}
  if(r.status==="approved"){const credentials={deviceId:r.deviceId,token:r.token};store(credentials);logLine("info","✅ Device approved; credentials saved locally.");return credentials}
 }
 throw Error("Pairing timed out. Re-run the command.");
}
async function portOpen(){const r=await fetch("http://127.0.0.1:8717/mcp",{signal:AbortSignal.timeout(1500)});return r.status>0;}
async function startGateway(){
 try{if(await portOpen())throw Error("Port 8717 is already occupied. Stop the other MCP gateway before connecting.")}catch(e){if(/occupied/.test(e.message))throw e}
 logLine("info","🚀 Starting local Desktop Commander gateway...");
 const fd=fs.openSync(path.join(process.env.TEMP||os.tmpdir(),"private-desktop-mcp-device.log"),"a");
 child=spawn(process.execPath,[path.join(root,"gateway.mjs")],{cwd:root,stdio:["ignore",fd,fd],windowsHide:true});fs.closeSync(fd);
 logLine("info","Gateway PID: "+child.pid+" | diagnostic log: "+path.join(process.env.TEMP||os.tmpdir(),"private-desktop-mcp-device.log"));
 for(let i=0;i<40;i++){if(child.exitCode!==null)throw Error("Gateway exited unexpectedly. See private-desktop-mcp-device.log");try{if(await portOpen()){logLine("info","🔌 Local Desktop Commander gateway ready (127.0.0.1:8717)");return}}catch{}await sleep(500)}
 throw Error("Gateway failed to listen on port 8717.");
}
function stopGateway(){if(child?.pid){if(process.platform==="win32")spawnSync("taskkill.exe",["/PID",String(child.pid),"/T","/F"],{windowsHide:true,timeout:8000});else child.kill("SIGTERM");child=null;}}
async function respond(ws,msg){
 const started=Date.now(),call=callInfo(msg.body,msg.id),callId=shortCallId(call.requestId);
 const name=call.label,isTool=call.method==="tools/call";
 allCalls++;sessionCalls++;
 logLine("info","🔧 ["+callId+"] "+(isTool?"Tool: ":"MCP: ")+name+" | "+requestBrief(call));
 if(debug)logLine("debug","    ↳ Metadata: "+requestDebug(call));
 if(trace)logLine("warn","    ↳ Trace args (locally visible): "+safeTraceRequest(call));
 const headers={};for(const k of ["accept","content-type","mcp-session-id","mcp-protocol-version","last-event-id","mcp-method","mcp-name"])if(msg.headers?.[k])headers[k]=msg.headers[k];
 try{const rpc=JSON.parse(String(msg.body||""));if(typeof rpc.method==="string"){headers["mcp-method"]=rpc.method;if(rpc.method==="tools/call"&&typeof rpc.params?.name==="string")headers["mcp-name"]=rpc.params.name;}}catch{}
 let response;
 try{
  const r=await fetch("http://127.0.0.1:8717/mcp",{method:msg.method||"POST",headers,body:msg.body,signal:AbortSignal.timeout(70000)});
  const body=await r.text(),forward={};for(const k of ["content-type","mcp-session-id","mcp-protocol-version"])if(r.headers.has(k))forward[k]=r.headers.get(k);
  response={kind:"response",id:msg.id,status:r.status,headers:forward,body:body.slice(0,8*1024*1024)};
 }catch(e){response={kind:"response",id:msg.id,status:502,headers:{"content-type":"application/json"},body:JSON.stringify({error:"Local gateway error",message:String(e.message).slice(0,180)})}}
 const result=responseBrief(response.body,response.headers?.["content-type"]||"",response.status);
 const failed=result.failed;
 if(failed){allFails++;sessionFails++;}
 logLine(failed?"error":"info",(failed?"❌":"✅")+" ["+callId+"] "+name+
  " | "+result.kind+" | HTTP "+response.status+" | "+formatElapsed(Date.now()-started));
 logLine(failed?"warn":"info","    ↳ "+result.summary);
 if(result.error)logLine("error","    ↳ JSON-RPC: "+result.error);
 if(debug)logLine("debug","    ↳ Response size: "+result.bytes+" bytes | Total calls: "+allCalls+" | Errors: "+allFails);
 if(trace)logLine("warn","    ↳ Trace output (may contain private data): "+safeTraceOutput(result));
 if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(response));
 else logLine("warn","    ↳ Response cannot be delivered: relay socket is not open");
}
async function connect(creds){return new Promise(resolve=>{
 const {wsAgent}=remoteTransport();
 const attempt=++connectionAttempt,opening=Date.now();
 logLine("info","🌐 Connecting to Cloudflare relay (attempt #"+attempt+")...");
 const ws=new WebSocket(relay.replace(/^https:/,"wss:")+"/relay/ws",{headers:{"Authorization":"Bearer "+creds.token,"X-Device-ID":creds.deviceId},handshakeTimeout:15000,...(wsAgent?{agent:wsAgent}:{})});socket=ws;
 let status=0;
 ws.on("open",()=>{
  connectedSince=Date.now();sessionCalls=0;sessionFails=0;lastError="";
  logLine("info","✅ Cloudflare relay connected in "+formatElapsed(Date.now()-opening));
  reportDevice(creds);
  console.log("CONNECTED. ChatGPT can now use this device. Ctrl+C to disconnect.");
 });
 ws.on("unexpected-response",(_req,res)=>{status=res.statusCode;res.resume();lastError="HTTP "+status;logLine("error","Relay handshake rejected: HTTP "+status)});
 ws.on("message",data=>{
  let m;try{m=JSON.parse(String(data))}catch{if(debug)logLine("debug","Ignored invalid relay JSON message");return}
  if(m.kind==="request")respond(ws,m).catch(e=>logLine("error","Request handler: "+sanitizeText(e.message,240)));
 });
 ws.on("error",e=>{lastError=sanitizeText(e.message,180);logLine("error","Relay network error: "+lastError)});
 ws.on("close",(code,reason)=>{
  socket=null;
  const uptime=connectedSince?formatElapsed(Date.now()-connectedSince):"not established";
  logLine("warn","🔌 Relay disconnected | code="+code+" | session uptime="+uptime+
   " | calls="+sessionCalls+" | failures="+sessionFails);
  if(lastError)logLine("warn","    ↳ Last network error: "+lastError);
  if(reason?.length)logLine("warn","    ↳ Close reason: "+sanitizeText(reason.toString(),100));
  connectedSince=0;
  resolve({unauthorized:status===401});
 });
})}
function stop(){if(stopping)return;stopping=true;logLine("info","Disconnecting PCC...");try{socket?.close(1000,"Manual disconnect")}catch{}stopGateway();setTimeout(()=>process.exit(0),200).unref();}
process.on("SIGINT",stop);process.on("SIGTERM",stop);
if(["help","--help","-h"].includes(command)){console.log("Private Desktop MCP: connect | status | reset [--safe | --debug | --trace]\nDefault: TRACE logs with redacted/truncated command and response previews (may contain private data).\nUse --safe for compact metadata-only logs, or --debug for detailed metadata without content previews.\nFirst connect requires approval at https://private-desktop-device-relay.ljx2043979076.workers.dev/admin/devices\nCtrl+C to disconnect. No automatic startup.");}
else if(command==="status"){console.log("Paired:",!!saved());try{console.log("Local HTTP:",(await fetch("http://127.0.0.1:8717/mcp",{signal:AbortSignal.timeout(2000)})).status)}catch{console.log("Local MCP offline")}}
else if(command==="reset"){forget();console.log("Local credentials cleared. Revoke old credentials in the admin page too.");}
else if(command==="connect"){
 logLine("info","╔══════════════ PCC REMOTE v0.3.6 ══════════════╗");
 logLine("info","Logging: "+(trace?"TRACE":debug?"DEBUG":"LIVE")+" | Gateway: Desktop Commander MCP");
 if(trace)logLine("warn","TRACE mode can display private user content in this terminal; do not share these logs.");
 logLine("info","╚═══════════════════════════════════════════════╝");
 try{const credentials=saved()||await pair();if(saved())logLine("info","💾 Stored device pairing found");await startGateway();let retries=0;
  while(!stopping){const r=await connect(credentials);if(r.unauthorized){forget();logLine("error","Credentials revoked; run again to pair.");break}if(stopping)break;retries++;const ms=Math.min(30000,1500*2**Math.min(5,retries));logLine("warn","Reconnecting in "+Math.ceil(ms/1000)+"s");await sleep(ms);}
 }catch(e){logLine("error","ERROR: "+sanitizeText(e.message,250));process.exitCode=1}finally{stopGateway()}
}else{console.error("Unknown command. Use help");process.exitCode=2}
