import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {spawnSync} from "node:child_process";

test("package entrypoints and canonical remote URL",()=>{
 const pkg=JSON.parse(fs.readFileSync("package.json","utf8"));
 assert.equal(pkg.bin["private-desktop-mcp"],"bin/cli.mjs");
 assert.equal(pkg.private,undefined);
 assert.match(pkg.name,/^@kfcheems\/private-desktop-mcp$/);
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
