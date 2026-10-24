import { spawnSync } from "node:child_process";
import { getProxyForUrl } from "proxy-from-env";

const proxyEnvironmentKeys=[
 "https_proxy","http_proxy","all_proxy",
 "npm_config_https_proxy","npm_config_http_proxy","npm_config_proxy"
];
export function hasEnvironmentProxy(env=process.env){
 const names=new Set(Object.keys(env).filter(k=>proxyEnvironmentKeys.includes(k.toLowerCase())));
 return [...names].some(k=>String(env[k]??"").trim().length>0);
}
export function normalizeProxy(value,source){
 const raw=String(value||"").trim();
 if(!raw)return {mode:"direct",source};
 const uri=/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)?raw:"http://"+raw;
 let parsed;
 try{parsed=new URL(uri)}catch{return {mode:"unsupported",source,reason:"Invalid proxy address"}}
 if(!["http:","https:"].includes(parsed.protocol)){
  return {mode:"unsupported",source,reason:"Proxy protocol "+parsed.protocol+" is not HTTP CONNECT; use an HTTP/Mixed proxy port"};
 }
 if(!parsed.hostname)return {mode:"unsupported",source,reason:"Missing proxy hostname"};
 return {mode:"proxy",source,url:parsed.href,description:parsed.protocol.slice(0,-1).toUpperCase()+" CONNECT via "+parsed.hostname+":"+(parsed.port||(["https:"].includes(parsed.protocol)?"443":"80"))};
}
export function queryWindowsProxy(url,{spawn=spawnSync}={}){
 // Windows WinINET system proxy, including static proxy, exclusions, PAC and WPAD.
 // Use the Windows user's configuration instead of guessing a Clash/v2rayN port.
 const target=String(url).replace(/'/g,"''");
 const script="$ErrorActionPreference='Stop';"
  +"$u=[Uri]'"+target+"';"
  +"$p=[System.Net.WebRequest]::GetSystemWebProxy();"
  +"if($p.IsBypassed($u)){[Console]::Out.Write('DIRECT')}"
  +"else{$v=$p.GetProxy($u);if($v.AbsoluteUri -eq $u.AbsoluteUri){[Console]::Out.Write('DIRECT')}else{[Console]::Out.Write($v.AbsoluteUri)}}";
 const result=spawn("powershell.exe",["-NoLogo","-NoProfile","-NonInteractive","-Command",script],{
  encoding:"utf8",timeout:6000,windowsHide:true,maxBuffer:4096
 });
 if(result.error||result.status!==0){
  return {mode:"unavailable",source:"windows",reason:result.error?.code==="ETIMEDOUT"?"Windows proxy lookup timed out":"Windows proxy lookup failed"};
 }
 const output=String(result.stdout||"").trim();
 if(output==="DIRECT")return {mode:"direct",source:"windows"};
 if(!output)return {mode:"unavailable",source:"windows",reason:"Windows proxy lookup returned no result"};
 return normalizeProxy(output,"windows");
}
export function resolveProxyForUrl(url,{
 platform=process.platform,env=process.env,envLookup=getProxyForUrl,windowsLookup=queryWindowsProxy
}={}){
 if(hasEnvironmentProxy(env)){
  const chosen=envLookup(url);
  return chosen?normalizeProxy(chosen,"environment"):{mode:"direct",source:"environment-bypass"};
 }
 if(platform==="win32")return windowsLookup(url);
 return {mode:"direct",source:"system"};
}
