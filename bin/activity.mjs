import path from "node:path";
import { sanitizeText, safeValue } from "./logging.mjs";

const OMIT="[hidden; use --trace to inspect local content]";
const safeId=value=>typeof value==="string"?sanitizeText(value,70):typeof value==="number"?String(value):"unknown";
const byteSize=value=>Buffer.byteLength(String(value??""),"utf8");
function compact(value,limit=140){
 return sanitizeText(String(value??""),limit);
}
export function parseRpc(body,contentType=""){
 let text=String(body||"");
 if(contentType.toLowerCase().includes("text/event-stream")){
  const candidates=text.split(/\r?\n/).filter(line=>line.startsWith("data:")).map(line=>line.slice(5).trim()).filter(s=>s&&s!=="[DONE]");
  for(let i=candidates.length-1;i>=0;i--){try{return JSON.parse(candidates[i])}catch{}}
 }
 try{return JSON.parse(text)}catch{return null}
}
export function callInfo(body,requestId=""){
 const r=parseRpc(body)||{},params=r.params&&typeof r.params==="object"?r.params:{};
 const name=typeof params.name==="string"?compact(params.name,80):"";
 const args=params.arguments&&typeof params.arguments==="object"?params.arguments:{};
 return {
  requestId:safeId(requestId),
  method:typeof r.method==="string"?compact(r.method,80):"unknown",
  name,
  jsonRpcId:safeId(r.id),
  args,
  label:name||compact(r.method||"unknown",80)
 };
}
export function requestBrief(call){
 const {args,name,method}=call;
 if(method==="tools/list")return "Discover available tools";
 if(method==="initialize")return "MCP session initialization";
 if(method==="notifications/initialized")return "MCP session established";
 if(method!=="tools/call")return method;
 const fields=[];
 if(typeof args.path==="string"){
  const filepath=args.path.replace(/\\/g,"/");
  fields.push("file="+compact(filepath.split("/").at(-1),72));
 }
 if(typeof args.pid==="number")fields.push("pid="+args.pid);
 if(typeof args.timeout_ms==="number")fields.push("timeout="+args.timeout_ms+"ms");
 if(typeof args.length==="number")fields.push("length="+args.length);
 if(typeof args.offset==="number")fields.push("offset="+args.offset);
 if(typeof args.shell==="string")fields.push("shell="+compact(args.shell,48));
 if(typeof args.command==="string")fields.push("command="+OMIT+" ("+args.command.length+" chars)");
 if(typeof args.content==="string")fields.push("content=[hidden] ("+args.content.length+" chars)");
 if(typeof args.name==="string")fields.push("name="+compact(args.name,56));
 return fields.join(" | ")||"parameters="+Object.keys(args).length+" fields";
}
export function requestDebug(call){
 return JSON.stringify({method:call.method,id:call.jsonRpcId,tool:call.name,arguments:safeValue(call.args,"arguments")});
}
function getTextBlocks(result){
 return Array.isArray(result?.content)?result.content.filter(x=>x?.type==="text"&&typeof x.text==="string").map(x=>x.text):[];
}
function safeResultSummary(result,textBlocks){
 if(Array.isArray(result?.tools))return "tools="+result.tools.length;
 if(result?.serverInfo&&typeof result.serverInfo.name==="string")return "server="+compact(result.serverInfo.name,56);
 const joined=textBlocks.join("\n");
 const hints=[];
 const process=joined.match(/Process started with PID\s+(\d+)/i);
 const complete=joined.match(/Process (?:completed|finished)(?: with exit code\s+(-?\d+))?/i);
 const reading=joined.match(/\[Reading\s+(\d+)\s+(?:new\s+)?lines?/i);
 if(process)hints.push("process PID="+process[1]);
 if(complete)hints.push(complete[1]===undefined?"process finished":"exit="+complete[1]);
 if(reading)hints.push("lines="+reading[1]);
 if(textBlocks.length)hints.push("text blocks="+textBlocks.length);
 if(joined)hints.push("output="+byteSize(joined)+" bytes");
 if(!hints.length&&result&&typeof result==="object")hints.push("fields="+Object.keys(result).length);
 return hints.join(" | ")||"no result";
}
export function responseBrief(body,contentType="",status=200){
 const rpc=parseRpc(body,contentType);
 const payloadSize=byteSize(body);
 if(!rpc)return {failed:status>=400,kind:"non-JSON response",summary:"response="+payloadSize+" bytes",error:"",bytes:payloadSize,trace:""};
 const error=rpc.error&&typeof rpc.error==="object"?rpc.error:null;
 const result=rpc.result&&typeof rpc.result==="object"?rpc.result:null;
 const blocks=getTextBlocks(result);
 const failed=Boolean(status>=400||error||result?.isError);
 const kind=error?"JSON-RPC error":result?.isError?"MCP tool error":failed?"HTTP error":"MCP response";
 const errorText=error?.message?compact(error.message,155):"";
 return {
  failed,kind,
  summary:result?safeResultSummary(result,blocks):"response="+payloadSize+" bytes",
  error:errorText,
  bytes:payloadSize,
  trace:blocks.join("\n")
 };
}
export function safeTraceRequest(call,limit=1200){
 const value=call.args;
 if(!value||typeof value!=="object")return "{}";
 const output={};
 for(const [key,entry] of Object.entries(value).slice(0,20)){
  if(/authorization|token|password|secret|credential|cookie|proof|api.?key/i.test(key))output[key]="[REDACTED]";
  else if(typeof entry==="string")output[key]=compact(entry,500);
  else output[key]=safeValue(entry,key);
 }
 return compact(JSON.stringify(output),limit);
}
export function safeTraceOutput(info,limit=1200){
 return info.trace?compact(info.trace,limit):"(no text content)";
}
export function shortCallId(id){
 const text=safeId(id);
 return text==="unknown"?"unknown":text.slice(0,8);
}
export function formatElapsed(ms){
 return ms>=1000?(ms/1000).toFixed(2)+"s":ms+"ms";
}
