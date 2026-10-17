/* Optional prototype browser gate. Requires development-only playwright-core and axe-core. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const moduleRoot=process.env.ASSERVAT_QA_NODE_MODULES;
if(!moduleRoot)throw new Error('Set ASSERVAT_QA_NODE_MODULES to a development node_modules directory');
const {chromium}=require(path.join(moduleRoot,'playwright-core'));
const axe=fs.readFileSync(path.join(moduleRoot,'axe-core/axe.min.js'),'utf8');
const base=process.env.ASSERVAT_UI_URL||'http://127.0.0.1:8765/design/ui/';
const executablePath=process.env.ASSERVAT_CHROMIUM;
let activeBrowser;
(async()=>{
 const browser=await chromium.launch({headless:true,...(executablePath?{executablePath}:{})});
 activeBrowser=browser;
 const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[],violations=[],external=[];let checks=0;
 page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!r.url().startsWith(base.replace('/design/ui/','/')))external.push(r.url());});
 await page.goto(base);const screens=await page.evaluate(()=>window.ASSERVAT_SCREENS);
 async function controls(){if(!(await page.locator('#prototype-dialog').isVisible()))await page.locator('#prototype-toggle').click();}
 async function done(){await page.locator('#prototype-done').click();}
 async function persona(p){await controls();await page.selectOption('#persona',p);await page.waitForFunction(p=>document.querySelector('#persona').value===p,p);await done();}
 async function route(id){await page.evaluate(id=>location.hash='#/'+id,id);await page.waitForFunction(id=>location.hash==='#/'+id&&document.querySelector('main').dataset.screen===id,id);await page.waitForTimeout(8);}
 async function state(s){await controls();await page.selectOption('#state-picker',s);await done();}
 for(const s of screens){
  await persona(s.personas.includes('admin')?'admin':s.personas[0]);await route(s.id);await state('normal');
  assert.equal(await page.locator('main h1').innerText(),s.title);checks++;
  await page.evaluate(axe);const results=await page.evaluate(async()=>await axe.run(document.querySelector('main'),{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}}));
  violations.push(...results.violations.map(v=>({screen:s.id,id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)})));
  for(const width of [390,320]){await page.setViewportSize({width,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${s.id} overflow at ${width}`);checks++;}
  await page.setViewportSize({width:1440,height:1050});
  for(const x of ['loading','empty','denied','expired','offline','quota']){await state(x);assert((await page.locator('main').innerText()).length>20);checks++;}
  await state('normal');
 }
 await persona('maintainer');await route('capture-compose');await page.locator('[data-profile="Live core"]').check();assert.match(await page.locator('main').innerText(),/may pause/);checks++;
 await route('capture-review');await page.locator('[data-action="capture"]').click();await page.waitForURL('**/#/capture-progress');await page.waitForFunction(()=>document.querySelector('main h1').textContent==='Capture C-1042');assert.match(await page.locator('main').innerText(),/Awaiting approval/);checks++;
 await route('recording-save');await page.locator('[data-action="save"]').click();await page.waitForURL('**/#/capture-progress');await page.waitForFunction(()=>document.querySelector('main h1').textContent==='Capture C-1042');assert.match(await page.locator('main').innerText(),/Saved existing recordings only/);assert.equal(await page.locator('tbody').innerText().then(s=>s.includes('Live core')),false);checks+=2;
 await route('capture-network');await page.locator('[data-setting="segments"]').fill('4');assert.match(await page.locator('#ring-size').innerText(),/8 MiB/);checks++;
 await page.locator('[data-action="survey"]').click();assert(await page.locator('#action-dialog').isVisible());await page.keyboard.press('Escape');assert(await page.locator('[data-action="survey"]').evaluate(e=>e===document.activeElement));checks+=2;
 await route('share-detail');await page.locator('[data-action="stop-sharing"]').click();await page.locator('#dialog-confirm').click();await page.waitForURL('**/#/shares');await page.waitForFunction(()=>document.querySelector('main h1').textContent==='Sharing you manage');assert.match(await page.locator('tbody').innerText(),/Active/);assert.match(await page.locator('tbody').innerText(),/Publishing stopped/);checks+=2;await route('share-detail');await page.locator('[data-action="revoke"]').click();await page.locator('#dialog-confirm').click();await page.waitForURL('**/#/shares');await page.waitForFunction(()=>document.querySelector('main h1').textContent==='Sharing you manage');assert.match(await page.locator('main').innerText(),/Revoked/);checks++;
 await persona('recipient');await route('case');assert.equal(await page.locator('main h1').innerText(),'Unavailable');assert(!(await page.locator('main').innerText()).includes('Checkout latency'));assert(!(await page.locator('#navigation').innerText()).includes('Workloads'));checks+=3;
 await route('shared-case');assert(!(await page.locator('main').innerText()).includes('Live core'));checks++;
 await persona('maintainer');await route('capture-review');await state('quota');assert(await page.locator('[data-action="capture"]').isDisabled());checks++;
 await state('normal');await page.setViewportSize({width:390,height:844});await page.locator('#menu-toggle').click();assert(await page.locator('#sidebar').isVisible());checks++;
 await page.setViewportSize({width:1440,height:1050});await state('normal');await persona('maintainer');await route('live-sources');
 await page.locator('a[href="#/live-watch"]').first().click();await page.waitForFunction(()=>document.querySelector('main h1').textContent==='Watch live');
 await page.selectOption('#live-projection','syscallMetadata');await page.locator('[data-action="live-open"]').click();await page.waitForFunction(()=>live.rows.length>0);assert.match(await page.locator('#live-rows').innerText(),/read|connect/);checks++;
 await page.locator('[data-action="live-inspect"]').first().click();assert.match(await page.locator('#live-selection').innerText(),/Selected approved observation/);checks++;await page.locator('[data-action="live-pause"]').click();const paused=await page.evaluate(()=>live.rows.length);await page.waitForTimeout(1100);assert.equal(await page.evaluate(()=>live.rows.length),paused);assert.match(await page.locator('#live-state').innerText(),/Paused/);checks+=2;
 await page.locator('[data-action="live-resume"]').click();await page.waitForFunction(n=>live.rows.length>n,paused);assert.match(await page.locator('#live-coverage').innerText(),/gaps/);checks++;
 await page.selectOption('#live-filter','errors');await page.waitForFunction(()=>live.rows.length>0);assert((await page.locator('#live-rows').innerText()).includes('ECONNREFUSED'));checks++;
 await controls();await page.getByText('Live-view simulation',{exact:true}).click();await page.locator('[data-action="live-gap"]').click();await done();assert.match(await page.locator('#live-coverage').innerText(),/counts of missed rows unknown/);checks++;
 await page.evaluate(()=>{live.rows.forEach(r=>r.created=Date.now()-31000);live.state='Paused';updateLive();});assert.equal(await page.evaluate(()=>live.rows.length),0);checks++;
 await page.locator('[data-action="live-close"]').click();assert.match(await page.locator('#live-state').innerText(),/Closed/);assert.equal(await page.evaluate(()=>live.rows.length),0);checks+=2;
 await page.selectOption('#live-projection','httpHeaders');await page.selectOption('#live-filter','all');await page.locator('[data-action="live-open"]').click();await page.waitForFunction(()=>live.rows.length>0);
 await page.waitForFunction(()=>live.rows.length>=7);await page.evaluate(()=>{document.querySelector('#notice').classList.remove('visible');document.activeElement.blur();});await page.screenshot({path:'design/ui/previews/live-watch.png',fullPage:true});await page.setViewportSize({width:390,height:844});await page.screenshot({path:'design/ui/previews/live-watch-mobile.png',fullPage:true});await page.setViewportSize({width:1440,height:1050});
 await state('denied');assert.equal(await page.evaluate(()=>live.rows.length),0);assert.equal(await page.locator('#live-rows').count(),0);checks+=2;
 await state('normal');await persona('recipient');await route('live-watch');assert.equal(await page.locator('main h1').innerText(),'Unavailable');assert(!(await page.locator('#navigation').innerText()).includes('Live sources'));checks+=2;
 await persona('maintainer');await route('overview');


 assert.equal(await page.locator('#prototype-dialog').isVisible(),false);checks++;
 assert.equal(await page.locator('#main').innerText().then(s=>/UI-\d{3}/.test(s)),false);checks++;
 assert.equal(await page.locator('#main .primary').count(),1);checks++;
 await page.locator('#prototype-toggle').click();await page.keyboard.press('Escape');assert(await page.locator('#prototype-toggle').evaluate(e=>e===document.activeElement));checks++;
 await route('capture-review');
 for(const label of ['Who can read','Workload impact','Possible user data','Automatic deletion']){assert(await page.getByText(label,{exact:true}).isVisible());checks++;}
 assert.equal(await page.getByText('Share selected results with Incident response when ready',{exact:true}).isVisible(),false);checks++;
 await page.getByText('Share results when ready (optional)',{exact:true}).click();assert(await page.getByText('Share selected results with Incident response when ready',{exact:true}).isVisible());checks++;
 await route('recordings');assert.equal(await page.locator('.section-nav [aria-current=page]').innerText(),'Recordings');checks++;
 await route('live-watch');assert(await page.locator('[data-action="live-open"]').isVisible());assert.equal(await page.locator('[data-action="live-resume"]').isVisible(),false);checks+=2;
 await page.locator('[data-action="live-open"]').click();assert.equal(await page.locator('[data-action="live-open"]').isVisible(),false);assert(await page.locator('[data-action="live-pause"]').isVisible());checks+=2;
 await page.waitForFunction(()=>live.rows.length>0);await page.locator('[data-action="live-inspect"]').first().focus();await page.waitForTimeout(1100);assert(await page.locator('[data-action="live-inspect"]').first().evaluate(e=>e===document.activeElement));checks++;
 await route('overview');
 // Follow task paths rather than only rendering screens: irrelevant settings,
 // direct save and a single review covering collection plus local investigation.
 await persona('maintainer');await route('capture-compose');
 async function profiles(names){for(const name of ['Context','HTTP headers','Syscall metadata','Go CPU profile','Live core'])await page.locator(`[data-profile="${name}"]`).setChecked(names.includes(name));}
 await profiles(['Context']);assert.equal(await page.getByText('Choose processes →',{exact:true}).count(),0);assert.equal(await page.getByText('Tune network capture →',{exact:true}).count(),0);checks+=2;
 await page.getByText('Review collection',{exact:true}).click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-review');assert.equal(await page.locator('[data-result-access]').count(),0);checks++;
 await route('capture-compose');await profiles(['Context','HTTP headers']);assert.equal(await page.getByText('Choose processes →',{exact:true}).count(),0);await page.getByText('Tune network capture →',{exact:true}).click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-network');checks+=2;
 await route('capture-compose');await profiles(['Context','Live core']);assert.equal(await page.getByText('Tune network capture →',{exact:true}).count(),0);await page.getByText('Choose processes →',{exact:true}).click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-processes');checks+=2;
 await page.getByText('Apply process rule',{exact:true}).click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-review');assert(await page.locator('[data-result-access]').isChecked());await page.locator('[data-result-agent]').check();assert.match(await page.locator('main').innerText(),/this browser and developer-agent/);checks+=2;
 await page.locator('[data-result-access]').uncheck();assert.match(await page.locator('main').innerText(),/Collection only/);await page.locator('[data-result-access]').check();checks++;
 await persona('approver');await route('approvals');assert.match(await page.locator('main').innerText(),/Available approval requests/);await route('approval');assert.match(await page.locator('main').innerText(),/Review collection and evidence access/);assert.match(await page.locator('main').innerText(),/registered developer-agent/);assert.equal(await page.locator('[data-action="approve"]').count(),1);checks+=4;
 await page.evaluate(()=>{document.querySelector('#notice').classList.remove('visible');document.activeElement.blur();});await page.screenshot({path:'design/ui/previews/investigation-approval.png',fullPage:true});
 await persona('maintainer');await route('recordings');await page.locator('[data-action="save-packet"]').click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-progress');assert.equal(await page.locator('#action-dialog').isVisible(),false);assert.match(await page.locator('tbody').innerText(),/Packet source/);assert.match(await page.locator('tbody').innerText(),/30 seconds/);assert.doesNotMatch(await page.locator('tbody').innerText(),/Syscall source|Live core/);checks+=4;
 await route('recordings');await page.locator('[data-action="save-syscall"]').click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-progress');assert.match(await page.locator('tbody').innerText(),/Syscall source/);assert.doesNotMatch(await page.locator('tbody').innerText(),/Packet source|Live core/);checks+=2;
 await route('recordings');await state('offline');assert(await page.locator('[data-action="save-packet"]').isDisabled());await state('normal');checks++;
 await route('live-watch');await page.selectOption('#live-projection','httpHeaders');await page.locator('[data-action="save-packet"]').click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-progress');assert.match(await page.locator('tbody').innerText(),/30 seconds/);assert.doesNotMatch(await page.locator('tbody').innerText(),/Syscall source|Live core/);checks+=2;
 await route('live-watch');await page.selectOption('#live-projection','syscallMetadata');await page.locator('[data-action="save-syscall"]').click();await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='capture-progress');assert.match(await page.locator('tbody').innerText(),/Syscall source/);checks++;

 await route('artifact-packets');await page.locator('[data-download-kind="pcap"]').click();await page.waitForURL('**/#/artifact-download');await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='artifact-download');assert.match(await page.locator('main').innerText(),/PCAPNG|Wireshark/);checks++;
 await page.locator('[data-action="download-file"]').click();assert.match(await page.locator('main').innerText(),/Completed \(simulation\)/);assert.equal(await page.locator('#action-dialog').isVisible(),false);checks+=2;
 await route('artifact-core');await page.locator('[data-download-kind="core"]').click();await page.waitForURL('**/#/artifact-download');await page.waitForFunction(()=>document.querySelector('main').dataset.screen==='artifact-download');assert.match(await page.locator('main').innerText(),/Your preferred compatible debugger/);assert.match(await page.locator('main').innerText(),/outside Asservat’s automatic deletion/);checks+=2;
 for(const kind of ['profile','logs','files','syscalls','command','http','derived','companion']){await page.selectOption('#download-kind',kind);assert(await page.locator('[data-action="download-file"]').isVisible());checks++;}
 await page.selectOption('#download-kind','core');await page.evaluate(()=>{demo.downloadGrant=false;render(false);});assert.equal(await page.locator('[data-action="download-file"]').count(),0);assert(await page.getByText('Request download access',{exact:true}).isVisible());checks+=2;
 await page.evaluate(()=>{demo.downloadGrant=true;demo.downloadState='Interrupted';render(false);});assert(await page.getByText('Resume download',{exact:true}).isVisible());checks++;
 await page.locator('[data-action="download-cancel"]').click();assert.equal(await page.locator('[data-action="download-file"]').count(),0);checks++;
 await page.evaluate(()=>{demo.downloadState='Preparing';render(false);});assert(await page.getByText('Preparing your download',{exact:true}).isVisible());assert.equal(await page.locator('[data-action="download-file"]').count(),0);assert(!(await page.locator('main').innerText()).includes('4 GiB'));checks+=3;await page.locator('[data-action="download-cancel"]').click();assert.match(await page.locator('main').innerText(),/Cancelled/);checks++;await state('loading');assert(await page.getByText('Cancel preparation',{exact:true}).isVisible());await page.locator('[data-action="download-cancel"]').click();assert.equal(await page.locator('#state-picker').inputValue(),'normal');checks+=2;
 await persona('recipient');await route('artifact-download');assert.equal(await page.locator('#download-kind option[value=core]').count(),0);checks++;
 await persona('maintainer');await route('artifact-download');await page.selectOption('#download-kind','core');await page.evaluate(()=>{document.querySelector('#notice').classList.remove('visible');document.activeElement.blur();});await page.screenshot({path:'design/ui/previews/download-core.png',fullPage:true});await page.selectOption('#download-kind','pcap');await page.evaluate(()=>document.activeElement.blur());await page.screenshot({path:'design/ui/previews/download-packets.png',fullPage:true});await state('offline');assert(await page.locator('[data-action="download-file"]').isDisabled());checks++;await state('normal');await route('overview');
 // Full shell accessibility, in addition to all screen bodies.
 await page.evaluate(axe);const shell=await page.evaluate(async()=>await axe.run({runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}}));violations.push(...shell.violations.map(v=>({screen:'shell',id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)})));
 await page.evaluate(()=>document.querySelector('#notice').classList.remove('visible'));
 for(const [id,file] of [['overview','workspace'],['capture-review','capture-review'],['artifact-packets','evidence']]){await route(id);await page.evaluate(()=>document.activeElement.blur());await page.screenshot({path:`design/ui/previews/${file}.png`,fullPage:true});}
 await route('capture-review');await page.setViewportSize({width:390,height:844});await page.screenshot({path:'design/ui/previews/mobile-review.png',fullPage:true});await page.setViewportSize({width:1440,height:1050});await persona('admin');await route('admin');await page.screenshot({path:'design/ui/previews/administration.png',fullPage:true});
 const report={date:'2026-10-09',scope:'Synthetic prototype only; not runtime security or accessibility certification',screens:screens.length,states:7,checks,browser:'Chromium headless',viewports:[1440,390,320],errors,externalRequests:external,accessibilityViolations:violations};
 fs.writeFileSync('docs/ux/prototype-validation.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));await browser.close();assert.equal(errors.length,0);assert.equal(external.length,0);assert.equal(violations.length,0);
})().catch(async e=>{console.error(e);if(activeBrowser)await activeBrowser.close();process.exitCode=1;});
