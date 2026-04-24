/**
 * cabinet.js — Case cabinet panel: list view & detail view.
 *
 * Renders 3 fake cases for UI/transition testing.
 * Back button in detail view returns to list without a scene transition.
 * Selecting a case card from D2 triggers D2→D3 via State.openCase().
 */

const Cabinet = (() => {

  // ── Fake case data ────────────────────────────────────────────────────────
  const CASES = [
    {
      id: 'case-001',
      ip: '20.89.234.17',
      geo: {
        country: 'United States',
        city: 'Boydton, VA',
        isp: 'Microsoft Azure',
        domain: 'azure.microsoft.com',
        hostname: 'azure-dc-east.cloudapp.net',
      },
      type: 'Port Scan',
      action: 'block_ip',
      verdict: 'block',
      classification: 'Malicious',
      confidence: 0.94,
      timestamp: '2026-04-04 · 14:32',
      agents: [
        { id: 'WH', name: 'WHOIS', finding: 'Registered to Microsoft Azure East US DC. However domain shows no legitimate reverse DNS — likely hijacked cloud VM.', fallback: false },
        { id: 'DN', name: 'DNS', finding: 'No PTR record. Forward lookup resolves to dead hostname. Zero associated mail infrastructure.', fallback: false },
        { id: 'PI', name: 'Port Intel', finding: '14 ports scanned in 8 seconds: 22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443, 8888, 27017, 27018, 27019, 9200. Classic reconnaissance sweep pattern.', fallback: false },
        { id: 'RP', name: 'Reputation', finding: 'AbuseIPDB score 98/100. Reported 312 times in last 30 days. Category: port scan, hacking, brute-force.', fallback: false },
      ],
      timeline: [
        { time: '14:31:52', event: 'First packet received from 20.89.234.17' },
        { time: '14:31:53', event: 'SYN flood on port 22 — 47 packets in 1.2s' },
        { time: '14:31:55', event: 'Sequential port scan detected (14 ports, 8s window)' },
        { time: '14:32:01', event: 'Reputation check returned score 98 — confirmed attacker' },
        { time: '14:32:03', event: 'Policy decision: BLOCK · IP written to block list' },
      ],
    },
    {
      id: 'case-002',
      ip: '45.33.32.156',
      geo: {
        country: 'United States',
        city: 'Fremont, CA',
        isp: 'Linode LLC',
        domain: 'linode.com',
        hostname: 'scanme.nmap.org',
      },
      type: 'Brute Force — SSH',
      action: 'alert_admin',
      verdict: 'alert',
      classification: 'Suspicious',
      confidence: 0.71,
      timestamp: '2026-04-04 · 13:11',
      agents: [
        { id: 'WH', name: 'WHOIS', finding: 'Linode LLC hosting. Known public test target (scanme.nmap.org). Legitimate use is possible — flagged for review.', fallback: false },
        { id: 'DN', name: 'DNS', finding: 'PTR record present: scanme.nmap.org. Associated with Nmap public scanning test host. Not inherently malicious.', fallback: false },
        { id: 'PI', name: 'Port Intel', finding: '382 SSH login attempts over 6 minutes. Password spray pattern — 12 unique usernames tried. Root, admin, ubuntu, pi, test…', fallback: false },
        { id: 'RP', name: 'Reputation', finding: 'AbuseIPDB score 45/100. Mixed reports — some false positives due to public test status. Inconclusive.', fallback: false },
      ],
      timeline: [
        { time: '13:05:14', event: 'SSH connection attempt #1 — user: root (failed)' },
        { time: '13:06:22', event: 'Connection rate exceeded threshold: 60 attempts/min' },
        { time: '13:08:45', event: 'Password spray pattern confirmed — 12 usernames' },
        { time: '13:11:03', event: 'Reputation score inconclusive (45/100, known test host)' },
        { time: '13:11:08', event: 'Policy decision: ALERT · Admin notified, monitoring active' },
      ],
    },
    {
      id: 'case-003',
      ip: '66.132.186.245',
      geo: {
        country: 'United States',
        city: 'Ann Arbor, MI',
        isp: 'Censys, Inc.',
        domain: 'censys.io',
        hostname: 'censys-scanner.com',
      },
      type: 'Internet Census Scan',
      action: 'log_only',
      verdict: 'log-only',
      classification: 'Benign',
      confidence: 0.82,
      timestamp: '2026-04-04 · 11:47',
      agents: [
        { id: 'WH', name: 'WHOIS', finding: 'Censys, Inc. — legitimate internet security research firm. ARIN registration current. Known academic/commercial scanning project.', fallback: false },
        { id: 'DN', name: 'DNS', finding: 'PTR record verified: censys-scanner.com. TXT record includes opt-out contact. Infrastructure consistent with declared scanner.', fallback: false },
        { id: 'PI', name: 'Port Intel', finding: 'Standard ZMap-style sweep on ports 80, 443, 8080. Low rate (3 packets/s). Consistent with Censys\'s known census methodology.', fallback: false },
        { id: 'RP', name: 'Reputation', finding: 'AbuseIPDB score 100/100 — BUT majority of reports are automated from IDS systems that flag all scanners. Human review: not malicious.', fallback: false },
      ],
      timeline: [
        { time: '11:46:58', event: 'Slow port sweep detected on 80, 443, 8080' },
        { time: '11:47:02', event: 'WHOIS lookup: Censys, Inc. — research scanner' },
        { time: '11:47:04', event: 'DNS PTR verified as censys-scanner.com with opt-out' },
        { time: '11:47:09', event: 'LLM judgment: legitimate scanner despite score=100' },
        { time: '11:47:11', event: 'Policy decision: LOG ONLY · No action taken' },
      ],
    },
  ];

  // ── Live agent map (backend snake_case → portrait + id) ──────────────────
  const LIVE_AGENT_MAP = {
    whois:      { id: 'WH', portrait: 'memory'       },
    dns:        { id: 'DN', portrait: 'auditory'      },
    port_intel: { id: 'PI', portrait: 'visual_cortex' },
    reputation: { id: 'RP', portrait: 'logic_center'  },
  };

  // ── Agent portrait mapping ────────────────────────────────────────────────
  // Maps agent id → portrait filename (no extension) in assets/agents/
  const AGENT_PORTRAITS = {
    WH: 'memory',        // WHOIS  — looking up historical records
    DN: 'auditory',      // DNS    — listening to domain resolution
    PI: 'visual_cortex', // Port Intel — scanning / seeing open ports
    RP: 'logic_center',  // Reputation — logical reasoning about threat scores
  };
  const PORTRAIT_FALLBACK = 'shivers';

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _verdictClass(action) {
    if (action === 'block_ip')    return 'block';
    if (action === 'alert_admin') return 'alert';
    if (action === 'log_only')    return 'log-only';
    return 'escalated';
  }

  function _verdictLabel(action) {
    if (action === 'block_ip')    return 'BLOCKED';
    if (action === 'alert_admin') return 'ALERTED';
    if (action === 'log_only')    return 'LOG ONLY';
    return 'ESCALATED';
  }

  // ── DOM builder: case card ────────────────────────────────────────────────

  function _buildCard(caseData) {
    const card = document.createElement('div');
    card.className = 'case-card';
    card.dataset.caseId = caseData.id;

    const vc = _verdictClass(caseData.action);
    const vl = _verdictLabel(caseData.action);

    card.innerHTML = `
      <div class="card-ip">${caseData.ip}</div>
      <div class="card-meta">${caseData.type}</div>
      <div class="card-footer">
        <span class="card-time">${caseData.timestamp}</span>
        <span class="verdict-stamp ${vc}">${vl}</span>
      </div>
    `;

    card.addEventListener('click', () => {
      State.openCase(caseData);
    });

    return card;
  }

  // ── DOM builder: detail view ──────────────────────────────────────────────

  function _buildDetail(caseData) {
    const vc = _verdictClass(caseData.action);
    const vl = _verdictLabel(caseData.action);
    const conf = Math.round(caseData.confidence * 100);

    // Agent chain HTML
    const agentsHtml = caseData.agents.map(a => {
      const portrait = AGENT_PORTRAITS[a.id] || PORTRAIT_FALLBACK;
      return `
        <div class="agent-entry${a.fallback ? ' fallback' : ''}">
          <div class="agent-icon-sm">
            <img src="assets/agents/${portrait}.png" alt="${a.name}" />
          </div>
          <div class="agent-body">
            <div class="agent-name-sm">${a.name}</div>
            <div class="agent-finding">${a.finding}</div>
          </div>
        </div>
      `;
    }).join('');

    // Timeline HTML
    const tlHtml = caseData.timeline.map(t => `
      <li>
        <span class="t-time">${t.time}</span>
        ${t.event}
      </li>
    `).join('');

    return `
      <div class="detail-section">
        <div class="detail-section-title">Source</div>
        <div class="geo-ip">${caseData.ip}</div>
        <table class="geo-table">
          <tr><td>Country</td><td>${caseData.geo.country}</td></tr>
          <tr><td>City</td><td>${caseData.geo.city}</td></tr>
          <tr><td>ISP</td><td>${caseData.geo.isp}</td></tr>
          <tr><td>Domain</td><td>${caseData.geo.domain}</td></tr>
          <tr><td>Host</td><td>${caseData.geo.hostname}</td></tr>
        </table>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">Agent Findings</div>
        ${agentsHtml}
      </div>

      <div class="detail-section">
        <div class="detail-section-title">Verdict</div>
        <div class="verdict-card">
          <div class="verdict-label-row">
            <span class="verdict-classification">
              Classification: <strong>${caseData.classification}</strong>
            </span>
            <span class="verdict-confidence">${conf}% confidence</span>
          </div>
          <div class="verdict-action-row">
            <span class="verdict-action-label">Decision:</span>
            <span class="verdict-stamp ${vc}">${vl}</span>
          </div>
        </div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">Timeline</div>
        <ul class="timeline">${tlHtml}</ul>
      </div>
    `;
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function _ensureStructure() {
    const panel = document.getElementById('cabinet-panel');
    if (panel.querySelector('#cabinet-list-view')) return; // already built

    panel.innerHTML = `
      <!-- LIST VIEW -->
      <div id="cabinet-list-view" class="cabinet-view">
        <div class="cabinet-header">
          <h2>Case Files</h2>
          <div class="case-count">${CASES.length} recent runs</div>
        </div>
        <div class="case-list"></div>
      </div>

      <!-- DETAIL VIEW -->
      <div id="cabinet-detail-view" class="cabinet-view">
        <div class="cabinet-header">
          <h2>Run Detail</h2>
          <button class="detail-back-btn" id="detail-back-btn">All Cases</button>
        </div>
        <div class="detail-scroll" id="detail-scroll"></div>
      </div>
    `;

    // Populate case list with fake cases
    const list = panel.querySelector('.case-list');
    CASES.forEach(c => list.appendChild(_buildCard(c)));

    // Back button
    panel.querySelector('#detail-back-btn').addEventListener('click', showList);

    // Load live history from server (prepends to fake cases)
    loadHistory();
  }

  // ── Live data ─────────────────────────────────────────────────────────────

  /** Called on `run_complete` WebSocket event — prepends a card to the list. */
  function addLiveRun(summary) {
    _ensureStructure();
    // live.py broadcasts: event_id, target (src_ip), final_action,
    // classification (policy_decision), confidence
    const action = summary.final_action || 'log_only';
    const stub = {
      id:             summary.event_id   || String(Date.now()),
      ip:             summary.target     || summary.src_ip || '?',
      type:           summary.event_type || 'Threat Detected',
      action:         action,
      verdict:        _verdictClass(action),
      classification: summary.classification || 'unknown',
      confidence:     summary.confidence     || 0,
      timestamp:      new Date().toLocaleString(),
      agents: [], timeline: [], geo: {},
      _liveEventId: summary.event_id,
    };
    const list = document.querySelector('.case-list');
    if (!list) return;
    list.insertBefore(_buildCard(stub), list.firstChild);

    // Update the run count in the header
    const countEl = document.querySelector('.case-count');
    if (countEl) {
      const total = list.querySelectorAll('.case-card').length;
      countEl.textContent = `${total} recent run${total !== 1 ? 's' : ''}`;
    }
  }

  /** Fetch last 10 runs from REST and add them as live cards. */
  function loadHistory() {
    fetch('/api/history')
      .then(r => r.json())
      .then(runs => runs.forEach(addLiveRun))
      .catch(() => {}); // offline — fake cases still show
  }

  /**
   * Called when a `__replay__` WebSocket message arrives.
   * If the detail view is active, hydrate it with the real agent data.
   */
  function hydrateDetail(events) {
    const dv = document.getElementById('cabinet-detail-view');
    if (!dv || !dv.classList.contains('active')) return;
    const caseData = _buildCaseFromReplay(events);
    if (caseData) showDetail(caseData);
  }

  function _buildCaseFromReplay(events) {
    let ip = '?', type = '?', action = 'log_only', classification = 'unknown';
    let confidence = 0;
    const geo = {};
    const agents = [];

    for (const e of events) {
      if (e.stage === 'event') {
        const r = e.raw || {};
        ip   = r.src_ip      || ip;
        type = r.event_type  || type;
      }
      if (e.stage === 'agent_report') {
        const r   = e.raw       || {};
        const n   = e.narration || {};
        const key = r.agent_name;
        const map = LIVE_AGENT_MAP[key] || { id: (key || '?').slice(0, 2).toUpperCase(), portrait: 'shivers' };
        agents.push({
          id:       map.id,
          name:     key || '?',
          finding:  n.inner_voice || '',
          fallback: !!r.fallback,
        });
        if (key === 'whois') {
          const f = r.findings || {};
          geo.country = f.country || '';
          geo.isp     = f.org    || '';
          geo.domain  = f.hosting_provider || '';
          geo.city    = f.city   || '';
        }
        if (key === 'dns') {
          geo.hostname = (r.findings || {}).hostname || '';
        }
      }
      if (e.stage === 'investigator_result') {
        const r    = e.raw || {};
        classification = r.classification    || classification;
        confidence     = r.confidence        || confidence;
        action         = r.recommended_action || action;
      }
      if (e.stage === 'policy_result') {
        action = (e.raw || {}).final_action || action;
      }
    }

    if (ip === '?') return null;
    return {
      id: ip, ip, type, action,
      verdict:        _verdictClass(action),
      classification, confidence,
      timestamp: new Date().toLocaleString(),
      geo: {
        country:  geo.country  || '?',
        city:     geo.city     || '?',
        isp:      geo.isp      || '?',
        domain:   geo.domain   || '?',
        hostname: geo.hostname || '?',
      },
      agents, timeline: [],
    };
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /** Build the panel structure and ensure case cards are rendered. */
  function reload() {
    _ensureStructure();
    // Wire the toggle tab button (safe to call multiple times)
    const tab = document.getElementById('panel-tab');
    if (tab && !tab._cabBound) {
      tab.addEventListener('click', toggle);
      tab._cabBound = true;
    }
  }

  /** Returns true when the cabinet panel is currently visible. */
  function isOpen() {
    return document.getElementById('cabinet-panel').classList.contains('visible');
  }

  /** Toggle the panel open/closed and sync the tab arrow. */
  function toggle() {
    const panel    = document.getElementById('cabinet-panel');
    const tab      = document.getElementById('panel-tab');
    const nowOpen  = panel.classList.toggle('visible');
    if (tab) tab.classList.toggle('panel-open', nowOpen);
  }

  /** Switch panel to list view (no scene transition). */
  function showList() {
    const lv = document.getElementById('cabinet-list-view');
    const dv = document.getElementById('cabinet-detail-view');
    if (!lv || !dv) return;
    lv.classList.remove('hidden');
    dv.classList.remove('active');
    dv.style.display = '';
  }

  /**
   * Switch panel to detail view for the given case.
   * Called after the D2→D3 transition completes.
   */
  function showDetail(caseData) {
    _ensureStructure();
    const lv = document.getElementById('cabinet-list-view');
    const dv = document.getElementById('cabinet-detail-view');
    const scroll = document.getElementById('detail-scroll');
    if (!lv || !dv || !scroll) return;

    scroll.innerHTML = _buildDetail(caseData);
    lv.classList.add('hidden');
    dv.style.display = 'flex';
    dv.classList.add('active');
    scroll.scrollTop = 0;

    // Request full replay AFTER D3 is active so hydrateDetail's guard passes.
    if (caseData._liveEventId) {
      WS.requestReplay(caseData._liveEventId);
    }
  }

  return { reload, showList, showDetail, isOpen, toggle, addLiveRun, hydrateDetail };

})();
