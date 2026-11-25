// Run with: node --test tests/test_demo_decisions_ui.cjs
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

class Element {
  constructor() { this.children = []; this.dataset = {}; this._text = ''; this.style = {}; this.classList = {toggle() {}}; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text; }
  set innerHTML(value) { this._html = value; this.children = []; }
  append(...elements) { this.children.push(...elements); }
  appendChild(element) { this.children.push(element); }
  replaceChildren(...elements) { this.children = elements; }
  querySelector() { return null; }
  focus() {}
  insertBefore(element, before) {
    const index = this.children.indexOf(before);
    this.children.splice(index < 0 ? this.children.length : index, 0, element);
  }
}

function setup() {
  const elements = new Map();
  const context = vm.createContext({
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
      },
      createElement() { return new Element(); },
    },
    setTimeout: () => 1, clearTimeout() {}, URLSearchParams, console,
  });
  const filename = path.join(__dirname, '../demo/static/decisions.js');
  vm.runInContext(fs.readFileSync(filename, 'utf8') + '\nthis.panel = new DecisionPanel();', context);
  return {panel: context.panel, context, el: id => elements.get(id)};
}

const record = changes => ({
  ts: '2026-11-19T00:32:00Z', request_id: 'req-1', session_id: 'session-fingerprint',
  agent: 'demo-example', phase: 'pre_call', action: 'strip-tools', route: 'quarantine',
  risk_score: 0.75, risk_level: 'high', enforce: true, ...changes,
});

test('response events and restored history cannot duplicate or reorder the latest decision', () => {
  const {panel, el} = setup();
  panel.add(record());
  panel.add(record());
  panel.add(record({ts: '2026-11-19T00:31:00Z', request_id: 'req-0', action: 'allow', risk_score: 0}));
  assert.equal(panel.records.size, 2);
  assert.equal(el('latest-action').textContent, 'strip-tools');
  assert.equal(el('latest-risk-score').textContent, '0.750');
  assert.equal(el('s-allow').textContent, '1');
  assert.equal(el('s-strip').textContent, '1');
});

test('missing metrics stay unknown; observation mode never claims tools were removed', () => {
  const {panel, el} = setup();
  panel.add(record({risk_score: undefined, risk_level: undefined, route: undefined, enforce: false}));
  assert.equal(el('latest-risk-score').textContent, '—');
  assert.equal(el('latest-risk-level').textContent, '—');
  assert.match(el('decision-explanation').textContent, /Observation only/);
  assert.doesNotMatch(el('decision-explanation').textContent, /Tools removed/);
  assert.equal(el('latest-action').textContent, 'observe');
  assert.equal(el('s-strip').textContent, '0');
});

test('detailed audit-only blocks stay observations in every action cell and counter', () => {
  const {panel, el} = setup();
  panel.add(record({action: 'block', enforce: false}));
  assert.equal(el('latest-action').textContent, 'observe');
  assert.equal(el('s-block').textContent, '0');
  const card = el('log-entries').children[0];
  assert.equal(card.children[1].children[3].children[1].textContent, 'observe');
  assert.match(card.children[2].children[1].textContent, /"action": "block"/);
});

test('a pending response for the previous browser session is discarded', async () => {
  const {panel, context} = setup();
  let resolve;
  context.fetch = () => new Promise(r => { resolve = r; });
  const pending = panel.restore('old-session', 'session');
  panel.reset();
  resolve({ok: true, json: async () => ({source: 'cloudwatch', status: 'ready', records: [record()]})});
  await pending;
  assert.equal(panel.records.size, 0);
  assert.equal(panel.session, null);
});

test('a new turn receives decisions without polling or history network calls', () => {
  const {panel, context} = setup();
  context.fetch = () => assert.fail('live decisions must arrive in stream events');
  context.setTimeout = () => assert.fail('no periodic history/log polling');
  panel.begin('live-session', 'session');
  panel.add(record({decision_id: 'd1'}));
  panel.finish();
  assert.equal(panel.records.size, 1);
});

test('admin history can enrich one minimal response decision without duplicating its counter', () => {
  const {panel, el} = setup();
  panel.add({decision_id: 'same', action: 'strip-tools'});
  assert.equal(el('latest-risk-score').textContent, '—');
  panel.add(record({decision_id: 'same'}));
  assert.equal(panel.records.size, 1);
  assert.equal(el('s-strip').textContent, '1');
  assert.equal(el('latest-risk-score').textContent, '0.750');
});

test('CloudWatch exports are explicitly recorded and split by agent and session', async () => {
  const {panel, el} = setup();
  const values = [
    {'@message': JSON.stringify(record())},
    {'@message': record({agent: 'other-agent', action: 'allow', risk_score: 0})},
  ];
  await panel.loadFile({size: 1000, text: async () => JSON.stringify(values)});
  assert.equal(panel.recorded, true);
  assert.equal(panel.records.size, 1);
  assert.equal(el('recorded-session').children.length, 2);
  assert.match(el('decision-status').textContent, /not the current live session/);
  panel.showArchive(JSON.stringify(['other-agent', 'session-fingerprint']));
  assert.equal(panel.records.size, 1);
  assert.equal(el('latest-action').textContent, 'allow');
  assert.equal(el('latest-risk-score').textContent, '0.000');
  panel.begin('new-live', 'session');
  assert.equal(panel.recorded, false);
  assert.equal(panel.records.size, 0);
});

test('log labels are rendered as text, never interpreted as HTML', () => {
  const {panel, el} = setup();
  const label = '<img src=x onerror=alert(1)>';
  panel.add(record({action: label, agent: label}));
  assert.equal(el('latest-action').textContent, label);
  assert.equal(el('latest-action')._html, undefined);
});

function setupPage({storedMode = 'session', available = ['session', 'stateless'], snapshot, restore} = {}) {
  const {context, el} = setup();
  const storage = new Map([['securelitellm-ui-session', 'old-ui-handle'], ['securelitellm-ui-mode', storedMode]]);
  const requests = [];
  let random = 0;
  context.sessionStorage = {getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value)};
  context.crypto = {getRandomValues: array => array.fill(++random)};
  context.Uint8Array = Uint8Array;
  context.clearInterval = () => {};
  context.fetch = async url => {
    requests.push(url);
    if (url === '/config') return {json: async () => ({available_modes: available, work_beats: []})};
    if (url.startsWith('/session/')) {
      if (restore) return restore();
      return {ok: true, json: async () => snapshot || {exists: false}};
    }
    return {ok: true, json: async () => ({records: [], status: 'waiting'})};
  };
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../demo/static/session.js'), 'utf8'), context);
  const html = fs.readFileSync(path.join(__dirname, '../demo/static/index.html'), 'utf8');
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return {context, el, storage, requests};
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('HTTP LAN pages generate unpredictable handles without crypto.randomUUID', async () => {
  const {context} = setupPage();
  await settle();
  const first = vm.runInContext('newUiSessionId()', context);
  assert.match(first, /^demo-[a-f0-9]{32}$/);
  assert.notEqual(vm.runInContext('newUiSessionId()', context), first);
  context.crypto.randomUUID = () => 'secure-context-uuid';
  assert.equal(vm.runInContext('newUiSessionId()', context), 'demo-secure-context-uuid');
});

test('refresh restores visible conversation and explicitly identifies the retained session', async () => {
  const {context, el, storage} = setupPage({snapshot: {
    exists: true, mode: 'session', pending_approval: false,
    events: [{kind: 'user_message', content: 'Earlier request'}, {kind: 'assistant_message', content: 'Earlier reply'}],
  }});
  await settle();
  const messages = el('messages').children.map(child => child._html || '').join(' ');
  assert.match(messages, /Existing session restored/);
  assert.match(messages, /Earlier request/);
  assert.match(messages, /Earlier reply/);
  assert.equal(storage.get('securelitellm-ui-session'), 'old-ui-handle');
  assert.equal(vm.runInContext('restoring', context), false);
});

test('an unavailable stored mode mints a fresh handle before chat or history access', async () => {
  const {context, storage, requests} = setupPage({storedMode: 'stateless', available: ['session']});
  await settle();
  assert.equal(vm.runInContext('MODE', context), 'session');
  assert.equal(storage.get('securelitellm-ui-mode'), 'session');
  assert.notEqual(storage.get('securelitellm-ui-session'), 'old-ui-handle');
  assert.equal(requests.some(url => url.includes('old-ui-handle')), false);
});

test('failed or late restoration cannot hide earlier context behind an empty active session', async () => {
  const failed = setupPage({restore: async () => { throw Error('offline'); }});
  await settle();
  assert.notEqual(failed.storage.get('securelitellm-ui-session'), 'old-ui-handle');
  let resolve;
  const late = setupPage({restore: () => new Promise(r => { resolve = r; })});
  await settle();
  vm.runInContext('newSession()', late.context);
  resolve({ok: true, json: async () => ({exists: true, mode: 'session', events: [{kind: 'assistant_message', content: 'Stale hidden context'}]})});
  await settle();
  assert.equal(late.el('messages').children.length, 0);
});
