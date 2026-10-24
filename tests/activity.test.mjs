import test from "node:test";
import assert from "node:assert/strict";
import {parseRpc,callInfo,requestBrief,requestDebug,responseBrief,safeTraceRequest,safeTraceOutput,shortCallId,formatElapsed,loggingOptions} from "../bin/activity.mjs";

const request=(name,args)=>JSON.stringify({jsonrpc:"2.0",id:7,method:"tools/call",params:{name,arguments:args}});
const reply=(result)=>JSON.stringify({jsonrpc:"2.0",id:7,result});

test("tool call logs contain correlation ID, safe fields and hidden command",()=>{
 const c=callInfo(request("start_process",{command:"echo private payload",timeout_ms:3000,shell:"powershell",token:"secret"}),"abcde123-ffff");
 const s=requestBrief(c);
 assert.equal(shortCallId(c.requestId),"abcde123");
 assert.match(s,/timeout=3000ms/);
 assert.match(s,/powershell/);
 assert.match(s,/hidden/);
 assert.doesNotMatch(s,/private payload/);
 const d=requestDebug(c);
 assert.doesNotMatch(d,/private payload|secret/);
 assert.equal(c.name,"start_process");
});
test("read_file summary shows basename only by default",()=>{
 const call=callInfo(request("read_file",{path:"C:\\Users\\Alice\\private\\document.txt",length:60}),"uuid");
 const brief=requestBrief(call);
 assert.match(brief,/document\.txt/);
 assert.match(brief,/length=60/);
 assert.doesNotMatch(brief,/Alice|private/);
});
test("HTTP 200 with isError is logged as MCP tool failure",()=>{
 const out=responseBrief(reply({isError:true,content:[{type:"text",text:"ENOENT private file"}]}),"application/json",200);
 assert.equal(out.failed,true);
 assert.equal(out.kind,"MCP tool error");
 assert.ok(out.summary.includes("text blocks=1"));
 assert.ok(!out.summary.includes("private file"));
});
test("process started PID and bytes are shown without leaking stdout text",()=>{
 const out=responseBrief(reply({content:[{type:"text",text:"Process started with PID 41912 (shell: powershell.exe)\nInitial output:\nSecret content"}]}),"application/json",200);
 assert.equal(out.failed,false);
 assert.match(out.summary,/PID=41912/);
 assert.match(out.summary,/output=\d+ bytes/);
 assert.doesNotMatch(out.summary,/Secret content/);
});
test("read_process_output line count, process completion and error codes",()=>{
 const out=responseBrief(reply({content:[{type:"text",text:"[Reading 31 new lines (total: 48 lines)]\nProcess completed with exit code 1"}]}),"application/json",200);
 assert.match(out.summary,/lines=31/);
 assert.match(out.summary,/exit=1/);
});
test("initialize and tools/list report safe metadata",()=>{
 assert.match(requestBrief(callInfo(JSON.stringify({method:"initialize",id:1,params:{clientInfo:{name:"ChatGPT"}}}))),/initialization/);
 const out=responseBrief(reply({tools:[{name:"read_file"},{name:"start_process"}]}),"application/json",200);
 assert.match(out.summary,/tools=2/);
});
test("streamable HTTP SSE JSON-RPC response detection",()=>{
 const body='event: message\ndata: {"jsonrpc":"2.0","id":7,"result":{"isError":true,"content":[{"type":"text","text":"Failed"}]}}\n\n';
 const out=responseBrief(body,"text/event-stream",200);
 assert.equal(out.failed,true);
 assert.equal(out.kind,"MCP tool error");
});
test("JSON-RPC error includes sanitized human-readable message",()=>{
 const out=responseBrief(JSON.stringify({jsonrpc:"2.0",error:{code:-32000,message:"Unable to read file"}}),"application/json",200);
 assert.equal(out.failed,true);
 assert.match(out.error,/Unable to read file/);
});
test("trace previews are explicit opt-in and redact recognizable credentials",()=>{
 const call=callInfo(request("start_process",{command:"echo hello token=supersecret password=hardpass"}),"id");
 const trace=safeTraceRequest(call);
 assert.match(trace,/echo hello/);
 assert.doesNotMatch(trace,/supersecret|hardpass/);
 const result=responseBrief(reply({content:[{type:"text",text:"user output api_key=secrettoken"}]}),"application/json",200);
 assert.doesNotMatch(safeTraceOutput(result),/secrettoken/);
});
test("duration and response length are bounded",()=>{
 assert.equal(formatElapsed(999),"999ms");
 assert.equal(formatElapsed(1500),"1.50s");
 const out=responseBrief("not json","text/plain",502);
 assert.equal(out.failed,true);
 assert.equal(out.kind,"non-JSON response");
 assert.equal(parseRpc("{}", "application/json")?.error,undefined);
});

test("TRACE is default without optional logging flags",()=>{
 for(const args of [[],["connect"],["connect","--trace"]]){
  assert.deepEqual(loggingOptions(args),{trace:true,debug:true,mode:"TRACE"});
 }
});
test("explicit logging reductions preserve user control",()=>{
 assert.deepEqual(loggingOptions(["connect","--debug"]),{trace:false,debug:true,mode:"DEBUG"});
 assert.deepEqual(loggingOptions(["connect","--safe"]),{trace:false,debug:false,mode:"LIVE"});
 assert.deepEqual(loggingOptions(["connect","--safe","--trace"]),{trace:false,debug:false,mode:"LIVE"});
});
