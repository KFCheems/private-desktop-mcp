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
import { logLine, rpcDescription, rpcOutcome, sanitizeText } from "./logging.mjs";

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const command=process.argv.slice(2).find(a=>!a.startsWith("--"))||"connect",debug=process.argv.includes("--debug"),relay="https://private-desktop-device-relay.ljx2043979076.workers.dev";
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
 for(let i=0;i<40;i++){if(child.exitCode!==null)throw Error("Gateway exited unexpectedly. See private-desktop-mcp-device.log");try{if(await portOpen()){logLine("info","🔌 Local Desktop Commander gateway ready (127.0.0.1:8717)");return}}catch{}await sleep(500)}
 throw Error("Gateway failed to listen on port 8717.");
}
function stopGateway(){if(child?.pid){if(process.platform==="win32")spawnSync("taskkill.exe",["/PID",String(child.pid),"/T","/F"],{windowsHide:true,timeout:8000});else child.kill("SIGTERM");child=null;}}
async function respond(ws,msg){
 const started=Date.now(),request=rpcDescription(msg.body);
 const title=request.name?request.method+" "+request.name:request.method;
 logLine("info","🔧 Received "+title);
 if(debug)logLine("debug","Request parameters: "+JSON.stringify(request.params));
 const headers={};for(const k of ["accept","content-type","mcp-session-id","mcp-protocol-version","last-event-id","mcp-method","mcp-name"])if(msg.headers?.[k])headers[k]=msg.headers[k];
 try{const rpc=JSON.parse(String(msg.body||""));if(typeof rpc.method==="string"){headers["mcp-method"]=rpc.method;if(rpc.method==="tools/call"&&typeof rpc.params?.name==="string")headers["mcp-name"]=rpc.params.name;}}catch{}
 let response;
 try{
  const r=await fetch("http://127.0.0.1:8717/mcp",{method:msg.method||"POST",headers,body:msg.body,signal:AbortSignal.timeout(70000)});
  const body=await r.text(),forward={};for(const k of ["content-type","mcp-session-id","mcp-protocol-version"])if(r.headers.has(k))forward[k]=r.headers.get(k);
  response={kind:"response",id:msg.id,status:r.status,headers:forward,body:body.slice(0,8*1024*1024)};
 }catch(e){response={kind:"response",id:msg.id,status:502,headers:{"content-type":"application/json"},body:JSON.stringify({error:"Local gateway error",message:String(e.message).slice(0,180)})}}
 const details=rpcOutcome(response.body,response.headers?.["content-type"]||"");
 const failed=response.status>=400||details.failed;
 logLine(failed?"error":"info",(failed?"❌ Failed ":"✅ Completed ")+title+" | HTTP "+response.status+" | "+(Date.now()-started)+"ms");
 if(debug)logLine("debug","Response metadata: "+JSON.stringify({kind:details.kind,bytes:details.size,resultFields:details.resultFields}));
 if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(response));
}
async function connect(creds){return new Promise(resolve=>{
 const {wsAgent}=remoteTransport();
 logLine("info","🌐 Connecting to Cloudflare relay...");
 const ws=new WebSocket(relay.replace(/^https:/,"wss:")+"/relay/ws",{headers:{"Authorization":"Bearer "+creds.token,"X-Device-ID":creds.deviceId},handshakeTimeout:15000,...(wsAgent?{agent:wsAgent}:{})});socket=ws;
 let status=0;
 ws.on("open",()=>{logLine("info","✅ Connected to Cloudflare relay");logLine("info","🟢 Device online: "+os.hostname());console.log("CONNECTED. ChatGPT can now use this device. Ctrl+C to disconnect.");});
 ws.on("unexpected-response",(req,res)=>{status=res.statusCode;res.resume();logLine("error","Relay refused: HTTP "+status)});
 ws.on("message",data=>{let m;try{m=JSON.parse(String(data))}catch{return}if(m.kind==="request")respond(ws,m).catch(e=>console.error(e.message))});
 ws.on("error",e=>logLine("error","Relay: "+sanitizeText(e.message,200)));
 ws.on("close",(code)=>{socket=null;logLine("warn","🔌 Relay disconnected (code "+code+")");resolve({unauthorized:status===401})});
})}
function stop(){if(stopping)return;stopping=true;logLine("info","Disconnecting PCC...");try{socket?.close(1000,"Manual disconnect")}catch{}stopGateway();setTimeout(()=>process.exit(0),200).unref();}
process.on("SIGINT",stop);process.on("SIGTERM",stop);
if(["help","--help","-h"].includes(command)){console.log("Private Desktop MCP: connect | status | reset [--debug]\nUse --debug for redacted request/response metadata.\nFirst connect requires approval at https://private-desktop-device-relay.ljx2043979076.workers.dev/admin/devices\nCtrl+C to disconnect. No automatic startup.");}
else if(command==="status"){console.log("Paired:",!!saved());try{console.log("Local HTTP:",(await fetch("http://127.0.0.1:8717/mcp",{signal:AbortSignal.timeout(2000)})).status)}catch{console.log("Local MCP offline")}}
else if(command==="reset"){forget();console.log("Local credentials cleared. Revoke old credentials in the admin page too.");}
else if(command==="connect"){
 logLine("info","PCC v0.3.4 starting ("+(debug?"debug":"normal")+" logging)");
 try{const credentials=saved()||await pair();if(saved())logLine("info","💾 Stored device pairing found");await startGateway();let retries=0;
  while(!stopping){const r=await connect(credentials);if(r.unauthorized){forget();logLine("error","Credentials revoked; run again to pair.");break}if(stopping)break;retries++;const ms=Math.min(30000,1500*2**Math.min(5,retries));logLine("warn","Reconnecting in "+Math.ceil(ms/1000)+"s");await sleep(ms);}
 }catch(e){logLine("error","ERROR: "+sanitizeText(e.message,250));process.exitCode=1}finally{stopGateway()}
}else{console.error("Unknown command. Use help");process.exitCode=2}
