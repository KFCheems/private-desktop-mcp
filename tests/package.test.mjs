import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {spawnSync} from "node:child_process";

test("package entrypoints and canonical remote URL",()=>{
 const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));
 assert.equal(pkg.bin["private-desktop-mcp"],"bin/cli.mjs");
 assert.equal(pkg.private,undefined);
 assert.match(pkg.name,/^@juexibobi\/private-desktop-mcp$/);
 const cli=fs.readFileSync("bin/cli.mjs","utf8");
 assert.ok(cli.includes("private-desktop-device-relay.ljx2043979076.workers.dev"));
 assert.ok(!cli.includes("qqking.top"));
 const result=spawnSync(process.execPath,["bin/cli.mjs","help"],{encoding:"utf8"});
 assert.equal(result.status,0,result.stderr);
 assert.match(result.stdout,/connect/);
});
test("server description advertises canonical endpoint",()=>{
 const json=JSON.parse(fs.readFileSync("server.json","utf8"));
 assert.equal(json.remotes[0].type,"streamable-http");
 assert.equal(json.remotes[0].url,"https://private-desktop-device-relay.ljx2043979076.workers.dev/mcp");
});

test("gateway and CLI imports are declared as direct dependencies and files are packed",()=>{
 const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));
 const serverJson=JSON.parse(fs.readFileSync("server.json","utf8"));
 assert.equal(serverJson.version,pkg.version);
 assert.ok(pkg.files.includes("bin/policy.mjs"));
 assert.ok(pkg.files.includes("bin/client-setup.mjs"));
 assert.ok(pkg.files.includes("skills/private-desktop-mcp/SKILL.md"));
 assert.ok(pkg.files.includes("AGENTS.md"));
 assert.ok(pkg.files.includes("docs/agent-install.md"));
 for(const file of ["gateway.mjs","bin/cli.mjs","bin/policy.mjs","bin/client-setup.mjs","bin/proxy.mjs"]){
  const source=fs.readFileSync(file,"utf8");
  for(const match of source.matchAll(/\bfrom\s+["']([^"']+)["']/g)){
   const spec=match[1];
   if(spec.startsWith("node:")||spec.startsWith(".")||spec.startsWith("/"))continue;
   const name=spec.startsWith("@")?spec.split("/").slice(0,2).join("/"):spec.split("/")[0];
   assert.ok(Object.hasOwn(pkg.dependencies,name),`${file} imports ${spec}, but ${name} is not a direct dependency`);
  }
 }
});

test("agent-native manifests and skill metadata are synchronized with package version",()=>{
 const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));
 for(const manifestPath of ["plugin.json",".claude-plugin/plugin.json","gemini-extension.json",".antigravity-plugin/plugin.json"]){
  const m=JSON.parse(fs.readFileSync(manifestPath,"utf8"));
  assert.equal(m.version,pkg.version,`${manifestPath} version mismatch`);
 }
 const marketplace=JSON.parse(fs.readFileSync(".claude-plugin/marketplace.json","utf8"));
 assert.equal(marketplace.plugins[0].name,"private-desktop-mcp");
 const skill=fs.readFileSync("skills/private-desktop-mcp/SKILL.md","utf8");
 assert.match(skill,/^---\r?\nname:\s*private-desktop-mcp/);
 assert.ok(fs.existsSync("AGENTS.md"));
 assert.ok(fs.existsSync("CLAUDE.md"));
 assert.ok(fs.existsSync("docs/agent-install.md"));
});

test("CLI report outputs valid sanitized JSON diagnostics",()=>{
 const res=spawnSync(process.execPath,["bin/cli.mjs","report","--readonly"],{encoding:"utf8"});
 assert.equal(res.status,0,res.stderr);
 const report=JSON.parse(res.stdout);
 assert.equal(report.policy.readonly,true);
 assert.equal(report.policy.dlp,true);
 assert.ok(typeof report.version==="string"&&report.version.length>0);
});
