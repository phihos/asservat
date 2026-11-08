// Test-only approved synthetic source events, real Go TLS/audited C13 routes
// and compiled React. No request/response interception or collector is used.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import * as valid from '../src/generated/validate-live.js';
const [origin] = process.argv.slice(2);
assert.equal(new URL(origin).hostname,'127.0.0.1');
assert.equal(new URL(origin).protocol,'https:');
const browser = await chromium.launch({headless:true,...(process.env.ASSERVAT_CHROMIUM?{executablePath:process.env.ASSERVAT_CHROMIUM}:{})});
const context = await browser.newContext({ignoreHTTPSErrors:true});
const page = await context.newPage();
const errors=[],foreign=[],calls=[],responses=[];
page.on('pageerror',e=>errors.push(e.message));
page.on('console',m=>{if(/violates.*Content Security Policy|Refused to (execute|apply|load)/i.test(m.text()))errors.push(m.text())});
page.on('request',r=>{const u=new URL(r.url());if(u.origin!==origin)foreign.push(r.url());if(u.pathname.startsWith('/api/v1/operations/'))calls.push({name:u.pathname.split('/').at(-1),input:r.postDataJSON()})});
page.on('response',r=>{if(new URL(r.url()).pathname.startsWith('/api/v1/operations/'))responses.push(r)});
// The console aborts an in-flight read_live_watch on pause/close; Chromium then
// discards that response's body. Such a body is unreadable to the page too, so
// only its status and headers are checked; every completed body still is.
const aborted=new Set();
page.on('requestfailed',q=>{if(new URL(q.url()).pathname.startsWith('/api/v1/operations/'))aborted.add(q)});
const json=async r=>{try{return await r.json()}catch(error){if(aborted.has(r.request()))return undefined;throw new Error(`${r.request().method()} ${new URL(r.url()).pathname} body: ${error.message}`)}};
const waitOp=name=>page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/operations/'+name&&r.request().method()==='POST');
async function checked(r,name){assert.equal(r.status(),200);const h=await r.request().allHeaders();assert.equal(h.origin,origin);assert.equal(h['x-csrf-token'],'C'.repeat(43));assert.equal(h.authorization,undefined);const out=await json(r);if(out===undefined&&aborted.has(r.request()))return out;assert(valid['validOutput_'+name](out),name+' generated output');assert.equal(out.status,'ok',JSON.stringify(out));return out}
const emit=async projection=>{const r=await page.evaluate(async({origin,projection})=>{const r=await fetch(origin+'/test/live-event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({projection})});return r.status},{origin,projection});assert.equal(r,204)};
try{
 await page.goto(origin+'/captures/new');
 await page.getByRole('link',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Collect evidence',exact:true})).toBeVisible();
 await page.getByRole('link',{name:'Watch live',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Observe existing recordings',exact:true})).toBeVisible();
 await page.getByLabel('Cluster ID',{exact:true}).fill('00000000-0000-4000-8000-000000000001');
 await page.getByLabel('Namespace',{exact:true}).fill('payments');
 await page.getByLabel('Workload or pod name',{exact:true}).fill('api');
 await page.getByRole('button',{name:'Use this target',exact:true}).click();
 const panel=page.getByRole('region',{name:'Live observation',exact:true});
 await expect(panel.getByRole('button',{name:'Find live sources',exact:true})).toBeVisible();
 assert.equal(calls.filter(c=>c.name.includes('live')).length,0,'attachment must not implicitly query');
 for(const [projection,label,expectedText,sourceIndex] of [['packetMetadata','Packet metadata','TCP 192.0.2.1:0; unknown; 0 wire bytes; PID unknown',0],['httpHeaders','Approved HTTP headers','GET status unknown; content-type: text/plain; request; duration unknown',1],['syscallMetadata','Syscall metadata','PID 1; read; no reported error; errno unknown; duration unknown; unpaired',2],['packetMetadata','Finite manual packet metadata','TCP 192.0.2.1:0; unknown; 0 wire bytes; PID unknown',3]]){
  const listWait=waitOp('list_live_sources');await panel.getByRole('button',{name:'Find live sources',exact:true}).click();const listed=await checked(await listWait,'list_live_sources');assert.equal(listed.data.sources.length,4);
  await panel.getByRole('checkbox').nth(sourceIndex).check();
  await panel.getByRole('combobox',{name:'Projection',exact:true}).selectOption(projection);
  const openWait=waitOp('open_live_watch');await panel.getByRole('button',{name:'Open live view',exact:true}).click();const opened=await checked(await openWait,'open_live_watch');assert.equal(opened.data.projection,projection);const originalEnd=opened.data.expires_at;
  await expect(panel.getByRole('table')).toHaveCount(0);
  await emit(projection);
  await expect(panel.getByRole('table',{name:'Approved live observations',exact:true})).toBeVisible();
  await expect(panel.getByText(expectedText,{exact:true})).toBeVisible();
  await panel.getByRole('button',{name:/^Inspect observation /}).first().click();
  await expect(panel.getByRole('region',{name:'Selected observation',exact:true})).toBeVisible();
  await expect(panel.getByText(/Gap: sensorLoss; count unknown/)).toBeVisible();
  const pauseWait=waitOp('update_live_watch');await panel.getByRole('button',{name:'Pause view',exact:true}).click();const paused=await checked(await pauseWait,'update_live_watch');assert.equal(paused.data.state,'Paused');assert.equal(paused.data.expires_at,originalEnd);await expect(panel.getByRole('table')).toBeVisible();
  await emit(projection); // underlying source continues, viewer pause does not stop it
  const resumeWait=waitOp('update_live_watch');await panel.getByRole('button',{name:'Resume from now',exact:true}).click();const resumed=await checked(await resumeWait,'update_live_watch');assert.equal(resumed.data.state,'Active');assert.equal(resumed.data.expires_at,originalEnd);await expect(panel.getByRole('table')).toHaveCount(0);
  await expect(panel.getByRole('region',{name:'Selected observation',exact:true})).toHaveCount(0);
  await emit(projection);await expect(panel.getByRole('table')).toBeVisible();
  const closeWait=waitOp('close_live_watch');await panel.getByRole('button',{name:'Close view',exact:true}).click();const closed=await checked(await closeWait,'close_live_watch');assert.equal(closed.data.state,'Closed');assert.equal(closed.data.expires_at,originalEnd);await expect(panel.getByRole('table')).toHaveCount(0);
  await panel.getByRole('button',{name:'Choose another live view',exact:true}).click();
  console.log(label+': real C13 rows/zero/null/loss, original deadline, pause/resume-head/close cleared');
 }
 for(const r of responses){const name=new URL(r.url()).pathname.split('/').at(-1);if(name.endsWith('live_watch')||name==='list_live_sources')await checked(r,name)}
 assert(calls.every(c=>c.name.endsWith('live_watch')||c.name==='list_live_sources'),'viewer must not acquire/save/download');
 assert.equal(await page.evaluate(()=>document.cookie),'');assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
 assert.deepEqual(errors,[]);assert.deepEqual(foreign,[]);
 console.log('Actual compiled React + TLS/session/CSRF + audited C20 + C13; synthetic authority/ledger/events, no SQL/node/collector qualification');
}finally{await context.close();await browser.close()}
