import test from "node:test";
import assert from "node:assert/strict";
import { hasEnvironmentProxy, normalizeProxy, queryWindowsProxy, resolveProxyForUrl } from "../bin/proxy.mjs";
const relay="https://private-desktop-device-relay.ljx2043979076.workers.dev";

test("Windows system HTTP/Mixed proxy gets selected when env proxy is not set",()=>{
 let called=0;
 const result=resolveProxyForUrl(relay,{platform:"win32",env:{NO_PROXY:"localhost"},windowsLookup:()=>{called++;return normalizeProxy("http://127.0.0.1:7890/","windows")}});
 assert.equal(called,1);
 assert.equal(result.source,"windows");
 assert.equal(result.mode,"proxy");
 assert.equal(new URL(result.url).port,"7890");
});
test("HTTP_PROXY or HTTPS_PROXY takes priority over Windows proxy",()=>{
 const result=resolveProxyForUrl(relay,{platform:"win32",env:{HTTPS_PROXY:"http://localhost:9090"},envLookup:()=> "http://localhost:9090",windowsLookup:()=>{throw Error("Should not use Windows")}});
 assert.equal(result.source,"environment");
 assert.equal(new URL(result.url).port,"9090");
});
test("NO_PROXY environment bypass remains direct even when Windows system proxy exists",()=>{
 const result=resolveProxyForUrl(relay,{platform:"win32",env:{HTTPS_PROXY:"http://localhost:9090",NO_PROXY:"*"},envLookup:()=> "",windowsLookup:()=>{throw Error("Should not use Windows")}});
 assert.equal(result.mode,"direct");
 assert.equal(result.source,"environment-bypass");
});
test("queryWindowsProxy uses Windows effective proxy and respects bypass",()=>{
 const fake=(file,args,opts)=>{
  assert.equal(file,"powershell.exe");
  assert.ok(args.includes("-NoProfile"));
  assert.ok(args.at(-1).includes("GetSystemWebProxy"));
  assert.ok(opts.timeout<=6000);
  return {status:0,stdout:"http://127.0.0.1:7890/\n"};
 };
 const output=queryWindowsProxy(relay,{spawn:fake});
 assert.equal(output.mode,"proxy");
 assert.equal(output.source,"windows");
 assert.equal(output.description,"HTTP CONNECT via 127.0.0.1:7890");
 assert.equal(queryWindowsProxy(relay,{spawn:()=>({status:0,stdout:"DIRECT"})}).mode,"direct");
});
test("system PAC/WPAD lookup timeout reports unavailable without crashing",()=>{
 const r=queryWindowsProxy(relay,{spawn:()=>({status:null,error:{code:"ETIMEDOUT"}})});
 assert.equal(r.mode,"unavailable");
 assert.match(r.reason,/timed out/);
});
test("unsupported SOCKS-only proxy gets a clear diagnostic instead of misusing HTTP agent",()=>{
 const r=normalizeProxy("socks5://127.0.0.1:1080","windows");
 assert.equal(r.mode,"unsupported");
 assert.match(r.reason,/HTTP CONNECT/);
});
test("non-Windows default remains direct unless environment proxy is configured",()=>{
 const r=resolveProxyForUrl(relay,{platform:"linux",env:{},windowsLookup:()=>{throw Error("Should not use Windows")}});
 assert.equal(r.mode,"direct");
});
test("Windows direct/bypass output is not mistaken for a proxy",()=>{
 const fake=()=>({status:0,stdout:"DIRECT"});
 assert.equal(queryWindowsProxy(relay,{spawn:fake}).mode,"direct");
});
test("proxy URI descriptions do not expose credentials",()=>{
 const r=normalizeProxy("http://a:secret@127.0.0.1:7890","windows");
 assert.equal(r.mode,"proxy");
 assert.ok(!r.description.includes("secret"));
});
