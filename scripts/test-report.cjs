// Optional DOM interaction checks. Runtime reports have no JavaScript dependencies.
// NODE_PATH=/tmp/gomodscan-ui-test/node_modules node scripts/test-report.cjs report.html
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {JSDOM, VirtualConsole} = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const errors = [];
const virtualConsole = new VirtualConsole();
virtualConsole.on('jsdomError', error => errors.push(error.message));
const dom = new JSDOM(html, {runScripts:'outside-only', virtualConsole, url:'https://report.test/'});
const {window} = dom;
const {document} = window;
window.HTMLElement.prototype.scrollIntoView = function() {};
const $ = selector => document.querySelector(selector);
const $$ = selector => Array.from(document.querySelectorAll(selector));
const visibleRows = () => $$('.dependency').filter(row => !row.hidden);
const event = (element, name) => element.dispatchEvent(new window.Event(name,{bubbles:true}));
const tick = () => new Promise(resolve => setTimeout(resolve,10));

(async () => {
 assert.equal(document.documentElement.classList.contains('js'),false);
 assert.equal($$('.view').length,5);
 assert.ok($$('.dependency').length > 0,'supply a report with dependencies');
 assert.ok($$('.dependency').every(row => !row.hidden),'no-JS dependencies must be accessible');
 assert.equal($$('script[src],link[rel="stylesheet"],iframe').length,0,'no external assets');
 // Exercise pagination with a large in-memory fixture based on real rendered markup.
 const original = $('.dependency');
 for (let i = 0; i < 60; i++) {
  const copy = original.cloneNode(true);
  copy.id = 'fixture-' + i;
  copy.dataset.path = 'fixture.example/pkg-' + String(i).padStart(2,'0');
  copy.dataset.security = '0'; copy.dataset.targetSecurity = '0';
  copy.dataset.securityStatus = 'checked'; copy.dataset.targetStatus = 'checked';
  copy.dataset.risk = 'low'; copy.dataset.update = i % 2 ? 'patch' : 'current';
  copy.dataset.type = i % 2 ? 'indirect' : 'direct';
  copy.querySelector('.dep-name code').textContent = copy.dataset.path;
  copy.querySelector('.dep-body').textContent = 'fixture detail';
  original.parentNode.insertBefore(copy,$('#no-results'));
 }
 const source = $('script').textContent;
 window.eval(source);
 assert.equal($('.view.active').id,'overview');
 assert.equal(visibleRows().length,25);
 $('#next').click(); assert.equal($('#page-count').textContent,'Sayfa 2 / 3');
 $('#next').click(); assert.ok(visibleRows().length <= 25); assert.equal($('#next').disabled,true);
 $('#previous').click(); assert.equal($('#page-count').textContent,'Sayfa 2 / 3');
 $('#search').value = 'no-such-package'; event($('#search'),'input');
 assert.equal(visibleRows().length,0); assert.equal($('#no-results').hidden,false);
 $('#reset').click(); assert.equal($('#page-count').textContent,'Sayfa 1 / 3');
 $('[data-filter="updates"]').click();
 assert.ok(visibleRows().every(row => ['major','minor','patch'].includes(row.dataset.update)));
 $('#type-filter').value = 'indirect'; event($('#type-filter'),'change');
 assert.ok(visibleRows().every(row => row.dataset.type === 'indirect'));
 assert.ok(visibleRows().length > 0);
 $('[data-mode="security"]').click();
 assert.equal($('.view.active').id,'dependencies');
 assert.ok(visibleRows().every(row => Number(row.dataset.security)+Number(row.dataset.targetSecurity)>0));
 $('#reset').click();
 $('#dependency-sort').value = 'name-desc'; event($('#dependency-sort'),'change');
 const names = visibleRows().map(row => row.dataset.path);
 assert.deepEqual(names,[...names].sort((a,b) => b.localeCompare(a,'tr')));
 const projectLink = $('[data-project-link]'); projectLink.click();
 assert.equal($('#project-filter').value,projectLink.dataset.projectLink);
 assert.ok(visibleRows().every(row => row.dataset.project === projectLink.dataset.projectLink));
 const action = $('[data-focus-path]');
 if (action) {
  action.click(); await tick();
  const opened = $$('.dependency').find(row => row.open);
  assert.ok(opened && !opened.hidden);
  assert.equal(opened.dataset.path,action.dataset.focusPath);
  assert.equal(document.activeElement,opened.querySelector('summary'));
 }
 $('#reset').click();
 const first = visibleRows()[0], second = visibleRows()[1];
 first.open = true; await tick(); second.open = true; await tick();
 assert.equal(first.open,false); assert.equal(second.open,true);
 const previousOpen = $$('details').filter(detail => detail.open);
 event(window,'beforeprint'); await tick();
 assert.ok($$('details').every(detail => detail.open),'printing expands all details');
 event(window,'afterprint'); await tick();
 assert.deepEqual($$('details').filter(detail => detail.open),previousOpen,'printing restores expansion state');
 const button = $('[data-sort="0"]'); button.click();
 assert.equal(button.parentElement.getAttribute('aria-sort'),'ascending');
 button.click(); assert.equal(button.parentElement.getAttribute('aria-sort'),'descending');
 window.location.hash = '#errors'; await tick();
 assert.equal($('.view.active').id,'errors');
 assert.equal($('nav a[aria-current="page"]').hash,'#errors');
 assert.deepEqual(errors,[]);
 console.log('PASS: offline fallback, filtering, search, sorting, pagination, navigation, focused details, accordion and print state');
 window.close();
})().catch(error => { console.error(error); window.close(); process.exitCode = 1; });
