const secretKey=/^(?:authorization|cookie|set-cookie|password|passwd|passphrase|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|private[_-]?key|credential|credentials|session[_-]?id|proof|pair[_-]?code|client[_-]?secret)$/i;
const contentKey=/^(?:command|body|content|text|stdin|script|source|data|payload|file_contents|file_content|new_string|old_string)$/i;
const secretInline=[
  /(Bearer\s+)[A-Za-z0-9._~+/-]+/gi,
  /((?:password|passwd|passphrase|token|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?)[^\s"'&,;]+/gi
];
export function timestamp(date=new Date()){
 return [date.getHours(),date.getMinutes(),date.getSeconds()].map(n=>String(n).padStart(2,"0")).join(":");
}
export function sanitizeText(value,max=200){
 let s=String(value).replace(/[\r\n\t]+/g," ");
 for(const re of secretInline)s=s.replace(re,"$1[REDACTED]");
 return s.length>max?s.slice(0,max)+"…":s;
}
export function safeValue(value,key="",depth=0){
 if(secretKey.test(key))return "[REDACTED]";
 if(contentKey.test(key))return "[omitted "+(typeof value==="string"?value.length:JSON.stringify(value??null).length)+" chars]";
 if(depth>=5)return "[nested]";
 if(typeof value==="string")return sanitizeText(value,160);
 if(typeof value==="number"||typeof value==="boolean"||value===null)return value;
 if(Array.isArray(value))return value.slice(0,8).map(v=>safeValue(v,"",depth+1));
 if(value&&typeof value==="object"){
   const out={};
   for(const [k,v] of Object.entries(value).slice(0,18))out[k]=safeValue(v,k,depth+1);
   return out;
 }
 return "[unknown]";
}
export function rpcDescription(body){
 try{
  const req=JSON.parse(String(body||""));
  const method=typeof req.method==="string"?sanitizeText(req.method,90):"unknown";
  const name=method==="tools/call"&&typeof req.params?.name==="string"?sanitizeText(req.params.name,100):"";
  return {method,name,params:safeValue(req.params??{},"params")};
 }catch{return {method:"unparseable",name:"",params:{}}}
}
export function rpcOutcome(body,contentType=""){
 let payload=String(body||"");
 if(contentType.includes("text/event-stream")){
  const data=payload.split(/\r?\n/).find(x=>x.startsWith("data:"));
  if(data)payload=data.slice(5).trim();
 }
 try{
  const rpc=JSON.parse(payload);
  const failed=Boolean(rpc.error||rpc.result?.isError);
  return {failed,size:Buffer.byteLength(String(body||""),"utf8"),kind:failed?"rpc-error":"rpc-ok",resultFields:rpc.result&&typeof rpc.result==="object"?Object.keys(rpc.result).slice(0,10):[]};
 }catch{
  return {failed:false,size:Buffer.byteLength(String(body||""),"utf8"),kind:"non-json",resultFields:[]};
 }
}
export function logLine(level,message){
 const tag={info:"INFO",warn:"WARN",error:"ERROR",debug:"DEBUG"}[level]||"INFO";
 const output="["+timestamp()+"] ["+tag+"] "+sanitizeText(message,1550);
 if(level==="error")console.error(output);else console.log(output);
}
