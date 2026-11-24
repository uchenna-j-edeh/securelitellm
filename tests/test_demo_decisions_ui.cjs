// Run with: node --test tests/test_demo_decisions_ui.cjs
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

class Element {
  constructor() { this.children = []; this.dataset = {}; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text; }
  set innerHTML(value) { this._html = value; this.children = []; }
  append(...elements) { this.children.push(...elements); }
  appendChild(element) { this.children.push(element); }
  replaceChildren(...elements) { this.children = elements; }
  querySelector() { return null; }
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
