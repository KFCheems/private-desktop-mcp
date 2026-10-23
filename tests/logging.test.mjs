import test from "node:test";
import assert from "node:assert/strict";
import { timestamp, sanitizeText, safeValue, rpcDescription, rpcOutcome } from "../bin/logging.mjs";

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
