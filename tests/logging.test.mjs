import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { timestamp, sanitizeText, safeValue, rpcDescription, rpcOutcome, logLine, setStdoutMode } from "../bin/logging.mjs";

test("local time is formatted as HH:MM:SS",()=>{
 assert.equal(timestamp(new Date(2026,0,2,3,4,5)),"03:04:05");
});
test("sensitive fields, commands, and file content are not written to debug logs",()=>{
 const req=rpcDescription(JSON.stringify({jsonrpc:"2.0",method:"tools/call",params:{name:"start_process",arguments:{command:"echo private-string",path:"C:/tmp",token:"supersecret",password:"mypassword",Authorization:"Bearer abc",timeout_ms:3000}}}));
 const printed=JSON.stringify(req.params);
 assert.equal(req.name,"start_process");
 assert.match(printed,/start_process/);
 assert.match(printed,/omitted/);
 for(const value of ["private-string","supersecret","mypassword","Bearer abc"]) assert.ok(!printed.includes(value),value);
 assert.ok(printed.includes("C:/tmp"));
});
test("inline secrets and terminal line breaks are redacted",()=>{
 const text=sanitizeText("Authorization: Bearer eyJabc.def\n token=supersecret\t api_key='anothersecret'");
 assert.ok(!text.includes("eyJabc.def"));
 assert.ok(!text.includes("supersecret"));
 assert.ok(!text.includes("anothersecret"));
 assert.ok(!text.includes("\n"));
});
test("response summaries never contain user file data",()=>{
 const body=JSON.stringify({jsonrpc:"2.0",result:{content:[{type:"text",text:"VERY_PRIVATE_CONTENT"}],isError:false}});
 const summary=rpcOutcome(body,"application/json");
 assert.equal(summary.failed,false);
 assert.ok(summary.size>0);
 assert.ok(!JSON.stringify(summary).includes("VERY_PRIVATE_CONTENT"));
});
test("detect application level errors even with HTTP 200",()=>{
 assert.equal(rpcOutcome(JSON.stringify({result:{isError:true}})).failed,true);
 assert.equal(rpcOutcome(JSON.stringify({error:{code:-32000,message:"Error"}})).failed,true);
 assert.equal(rpcOutcome('event: message\ndata: {"result":{"isError":true}}\n\n',"text/event-stream").failed,true);
});
test("truncate nested and long values in debug metadata",()=>{
 const val=safeValue({a:"q".repeat(500),nested:{session_id:"PRIVATESESSION",file_content:"a".repeat(2000)}});
 const s=JSON.stringify(val);
 assert.ok(s.length<500);
 assert.ok(!s.includes("PRIVATESESSION"));
 assert.ok(!s.includes("a".repeat(80)));
});
test("json stdout mode sends every human log line to stderr",()=>{
 const originalLog=console.log;
 const originalError=console.error;
 const out=[];
 const err=[];
 console.log=(...args)=>{out.push(args.join(" "));};
 console.error=(...args)=>{err.push(args.join(" "));};
 try{
  setStdoutMode("json");
  logLine("info","json-mode-info");
  logLine("warn","json-mode-warn");
  logLine("debug","json-mode-debug");
  logLine("error","json-mode-error");
  assert.deepEqual(out,[],"stdout must stay empty in json mode");
  assert.equal(err.length,4);
  for(const marker of ["json-mode-info","json-mode-warn","json-mode-debug","json-mode-error"]) assert.match(err.join("\n"),new RegExp(marker));

  setStdoutMode("text");
  logLine("info","text-mode-info");
  assert.equal(out.length,1,"text mode must keep info on stdout");
  assert.match(out[0],/text-mode-info/);
  assert.equal(err.length,4,"text mode must not add info lines to stderr");
 }finally{
  setStdoutMode("text");
  console.log=originalLog;
  console.error=originalError;
 }
});

function connectJsonEnv(homeDir,relayUrl){
 const env={...process.env,HOME:homeDir,USERPROFILE:homeDir,APPDATA:path.join(homeDir,"AppData","Roaming"),CI:"1",PCC_RELAY_URL:relayUrl,NO_PROXY:"127.0.0.1,localhost",no_proxy:"127.0.0.1,localhost"};
 for(const key of ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy","PCC_MCP_CONFIG","MCP_PORT"]) delete env[key];
 return env;
}

function spawnConnectJson({relayUrl,homeDir,timeoutMs}){
 return new Promise((resolve,reject)=>{
  const repoRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
  const child=spawn(process.execPath,["bin/cli.mjs","connect","--json","--relay",relayUrl,"--port","18717"],{
   cwd:repoRoot,
   env:connectJsonEnv(homeDir,relayUrl),
   stdio:["ignore","pipe","pipe"]
  });
  let stdout="";
  let stderr="";
  let timedOut=false;
  const timer=setTimeout(()=>{timedOut=true;child.kill("SIGTERM");},timeoutMs);
  child.stdout.on("data",(d)=>{stdout+=d;});
  child.stderr.on("data",(d)=>{stderr+=d;});
  child.on("error",(e)=>{clearTimeout(timer);reject(e);});
  child.on("close",(code)=>{clearTimeout(timer);resolve({stdout,stderr,code,timedOut});});
 });
}

test("connect --json writes only JSON events to stdout and diagnostics to stderr",async()=>{
 const tmpHome=fs.mkdtempSync(path.join(os.tmpdir(),"pcc-json-mode-"));
 const relayHome=fs.mkdtempSync(path.join(os.tmpdir(),"pcc-json-mode-refused-"));
 let server;
 try{
  // A stub relay answers the pairing handshake, then refuses every poll. This is the only way
  // to observe pairing_required without a real Cloudflare Worker; the CLI prints it after
  // /relay/pair/start succeeds and before the first (now refused) poll.
  server=http.createServer((req,res)=>{
   if(req.method==="POST"&&req.url==="/relay/pair/start"){
    res.writeHead(200,{"content-type":"application/json"});
    res.end(JSON.stringify({code:"TEST-CODE",approvalUrl:"http://127.0.0.1:9/approve",pairId:"pair-test",proof:"proof-test",expiresIn:3600}));
    server.close();
    return;
   }
   res.writeHead(503,{"content-type":"application/json"});
   res.end(JSON.stringify({error:"offline"}));
  });
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
  const relayUrl="http://127.0.0.1:"+server.address().port;

  const paired=await spawnConnectJson({relayUrl,homeDir:tmpHome,timeoutMs:2500});
  const lines=paired.stdout.split(/\r?\n/).filter((line)=>line.trim());
  assert.ok(lines.length>=1,"expected at least one JSON event on stdout");
  const events=lines.map((line)=>{
   try{return JSON.parse(line);}catch(e){throw new Error("non-JSON stdout line: "+line);}
  });
  assert.ok(events.some((e)=>e.event==="pairing_required"),"pairing_required must appear on stdout");
  assert.match(paired.stderr,/PCC REMOTE/,"the human banner must be on stderr");
  assert.ok(!paired.stdout.includes("PCC REMOTE"),"the human banner must not be on stdout");

  // Relay that refuses connections outright: the connect path still must not leak text onto stdout.
  const refused=await spawnConnectJson({relayUrl:"http://127.0.0.1:1",homeDir:relayHome,timeoutMs:8000});
  assert.equal(refused.timedOut,false,"connect against a refused relay must exit on its own");
  assert.notEqual(refused.code,0);
  for(const line of refused.stdout.split(/\r?\n/).filter((l)=>l.trim())) assert.doesNotThrow(()=>JSON.parse(line),"non-JSON stdout line: "+line);
  assert.match(refused.stderr,/PCC REMOTE/);
  assert.match(refused.stderr,/ERROR/);
 }finally{
  if(server){server.closeAllConnections?.();server.close();}
  fs.rmSync(tmpHome,{recursive:true,force:true});
  fs.rmSync(relayHome,{recursive:true,force:true});
 }
});
