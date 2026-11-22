/* Actual gateway audit records. Model prose is never treated as a policy decision. */
class DecisionPanel {
  constructor() {
    this.source = 'docker';
    this.generation = 0;
    this.records = new Map();
    this.timer = null;
    this.recorded = false;
    document.getElementById('decision-refresh').onclick = () => this.poll(this.generation);
    document.getElementById('decision-import').onclick = () => {
      if (!this.liveRunning) document.getElementById('decision-file').click();
    };
    document.getElementById('decision-file').onchange = event => this.loadFile(event.target.files[0]);
  }

  text(id, value) { document.getElementById(id).textContent = value; }
  status(state, message) {
    const el = document.getElementById('decision-status');
    el.dataset.status = state;
    const origin = this.recorded ? 'Recorded evidence · not the current live session' : `Live · ${this.source}`;
    el.textContent = `${origin} · ${message}`;
  }

  reset() {
    clearTimeout(this.timer);
    this.generation++;
    this.session = null;
    this.busy = false;
    this.liveRunning = false;
    this.recorded = false;
    this.records.clear();
    this.latest = null;
    document.getElementById('decision-summary').dataset.action = '';
    document.getElementById('decision-import').disabled = false;
    document.getElementById('decision-refresh').disabled = false;
    document.getElementById('recorded-session-row').hidden = true;
    document.getElementById('log-entries').innerHTML = '<div class="log-empty">No gateway decisions for this session yet.</div>';
    for (const id of ['latest-risk-score', 'latest-risk-level', 'latest-route', 'latest-action']) this.text(id, '—');
    this.text('decision-count', '0 decisions');
    for (const id of ['s-allow', 's-harden', 's-strip', 's-block']) this.text(id, '0');
    this.text('decision-explanation', "Run a task to see the gateway's decision alongside the agent's work.");
    this.text('decision-identity', '');
    this.status('waiting', 'waiting for a request.');
  }

  begin(session, mode) {
    if (this.recorded) this.reset();
    this.session = session;
    this.mode = mode;
    this.liveRunning = true;
    this.deadline = Infinity;
    document.getElementById('decision-import').disabled = true;
    this.status('waiting', 'collecting gateway decisions…');
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.poll(this.generation), 1000);
  }

  finish() {
    this.liveRunning = false;
    this.deadline = Date.now() + 30000; // Allow for CloudWatch's delivery delay.
    document.getElementById('decision-import').disabled = false;
    if (this.session && !this.recorded) {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.poll(this.generation), 2000);
    }
  }

  async poll(generation) {
    if (generation !== this.generation || this.recorded || !this.session || this.busy) return;
    this.busy = true;
    try {
      const params = new URLSearchParams({session_id: this.session, mode: this.mode});
      const response = await fetch('/decisions?' + params);
      if (!response.ok) throw new Error('unavailable');
      const batch = await response.json();
      if (generation !== this.generation || this.recorded) return;
      this.source = batch.source || this.source;
      for (const record of batch.records || []) this.add(record);
      this.status(batch.status, batch.message || 'Waiting for gateway decisions.');
    } catch (_) {
      if (generation === this.generation) this.status('error', 'Cannot reach the decision service. Refresh to retry.');
    } finally {
      if (generation === this.generation && !this.recorded) {
        this.busy = false;
        if (this.liveRunning || Date.now() < this.deadline) {
          clearTimeout(this.timer);
          this.timer = setTimeout(() => this.poll(generation), 2000);
        }
      }
    }
  }

  key(rec) {
    return JSON.stringify(['agent', 'session_id', 'request_id', 'phase', 'ts', 'action'].map(k => rec[k] ?? null));
  }

  score(rec) {
    return typeof rec.risk_score === 'number' && Number.isFinite(rec.risk_score)
      ? rec.risk_score.toFixed(3) : '—';
  }

  explanation(rec) {
    const meaning = {
      'allow': 'Request allowed to proceed. This does not by itself prove that an external action executed.',
      'strip-tools': 'Tools removed for this model request. A text reply can still be returned.',
      'hold': 'Proposed action held for review. It has not been approved for execution.',
      'block': 'Model request blocked by the gateway.',
      'route-hardened': 'Request sent to the hardened model route.',
      'approved': 'A reviewer approved the held action. Check the tool result for execution.',
      'denied': 'A reviewer denied the held action.',
    };
    if (rec.enforce === false) return `Observation only; enforcement is off. Proposed action: ${rec.action}.`;
    const prefix = '';
    const rules = Array.isArray(rec.matched_rules) ? rec.matched_rules.join(', ') : '';
    return prefix + (meaning[rec.action] || 'Gateway decision recorded.') + (rules ? ` Rule: ${rules}.` : '');
  }

  add(rec) {
    if (!rec || typeof rec !== 'object' || typeof rec.action !== 'string') return;
    const key = this.key(rec);
    if (this.records.has(key)) return;
    this.records.set(key, rec);
    const log = document.getElementById('log-entries');
    log.querySelector('.log-empty')?.remove();
    const card = document.createElement('article');
    card.className = 'dc';
    const head = document.createElement('div');
    head.className = 'dc-head';
    const phase = {pre_call: 'Before model', post_call: 'After model', approval: 'Review'}[rec.phase] || 'Decision';
    const date = new Date(rec.ts);
    const clock = Number.isNaN(date.getTime()) ? 'time unavailable' : date.toLocaleTimeString([], {hour12: false, timeZoneName: 'short'});
    head.textContent = `${phase} · ${clock}`;
    const grid = document.createElement('dl');
    grid.className = 'decision-grid';
    for (const [label, value] of [
      ['Risk score', this.score(rec)], ['Risk level', rec.risk_level || '—'],
      ['Route', rec.route || '—'], ['Action', rec.action],
    ]) {
      const group = document.createElement('div');
      const dt = document.createElement('dt');
      const dd = document.createElement('dd');
      dt.textContent = label;
      dd.textContent = value;
      group.append(dt, dd);
      grid.appendChild(group);
    }
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = 'Evidence details';
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(rec, null, 2);
    details.append(summary, pre);
    card.append(head, grid, details);
    // Insert in audit-time order so a late older event never becomes the latest decision.
    const timestamp = typeof rec.ts === 'string' ? rec.ts : '';
    card.dataset.timestamp = timestamp;
    const before = Array.from(log.children).find(el => (el.dataset.timestamp || '') <= timestamp);
    log.insertBefore(card, before || null);
    if (!this.latest || timestamp >= (this.latest.ts || '')) {
      this.latest = rec;
      document.getElementById('decision-summary').dataset.action = rec.enforce === false ? 'observe' : rec.action;
      this.text('latest-risk-score', this.score(rec));
      this.text('latest-risk-level', rec.risk_level || '—');
      this.text('latest-route', rec.route || '—');
      this.text('latest-action', rec.action);
      this.text('decision-explanation', this.explanation(rec));
      this.text('decision-identity', `Agent: ${rec.agent || '—'} · Session: ${rec.session_id || '—'} · ${rec.phase || '—'} · ${rec.ts || '—'}`);
    }
    this.text('decision-count', `${this.records.size} decision${this.records.size === 1 ? '' : 's'}`);
    const counts = {allow: 0, harden: 0, strip: 0, block: 0};
    for (const record of this.records.values()) {
      if (record.action === 'allow') counts.allow++;
      if (['hold', 'route-hardened'].includes(record.action)) counts.harden++;
      if (record.action === 'strip-tools') counts.strip++;
      if (record.action === 'block') counts.block++;
    }
    for (const [name, count] of Object.entries(counts)) this.text('s-' + name, count);
  }

  async loadFile(file) {
    if (!file || this.liveRunning) return;
    const generation = this.generation;
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error('Use a log export smaller than 2 MB.');
      const text = await file.text();
      if (generation !== this.generation || this.liveRunning) return;
      let values;
      try { values = JSON.parse(text); } catch (_) {
        values = text.split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line));
      }
      if (!Array.isArray(values)) values = [values];
      const records = values.map(value => {
        const record = value?.['@message'] ?? value;
        return typeof record === 'string' ? JSON.parse(record) : record;
      }).filter(rec => rec && typeof rec === 'object' && typeof rec.action === 'string'
        && typeof rec.session_id === 'string' && ['pre_call', 'post_call', 'approval'].includes(rec.phase));
      if (!records.length || records.length > 1000) throw new Error('Use an export containing 1–1000 gateway decisions.');
      this.reset();
      this.recorded = true;
      this.archive = records;
      const groups = [...new Set(records.map(rec => JSON.stringify([rec.agent || '', rec.session_id])))];
      const select = document.getElementById('recorded-session');
      select.replaceChildren();
      for (const group of groups) {
        const [agent, session] = JSON.parse(group);
        const option = document.createElement('option');
        option.value = group;
        option.textContent = `${agent || 'agent unknown'} · ${session}`;
        select.appendChild(option);
      }
      select.onchange = () => this.showArchive(select.value);
      document.getElementById('recorded-session-row').hidden = false;
      document.getElementById('decision-refresh').disabled = true;
      this.showArchive(groups[0]);
    } catch (error) {
      this.status('error', 'Could not load recorded evidence. ' + error.message);
    } finally {
      document.getElementById('decision-file').value = '';
    }
  }

  showArchive(group) {
    const [agent, session] = JSON.parse(group);
    this.records.clear();
    this.latest = null;
    document.getElementById('log-entries').replaceChildren();
    const selected = this.archive.filter(rec => (rec.agent || '') === agent && rec.session_id === session);
    selected.sort((a, b) => (a.ts || '').localeCompare(b.ts || '')).forEach(rec => this.add(rec));
    this.status('recorded', 'saved audit records; not a live replay. Start a new session to return to live mode.');
  }
}
