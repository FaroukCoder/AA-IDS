/**
 * logic.js — All WebSocket, state, API, and event-handling logic.
 *
 * To change a stage handler or UI behaviour: edit this file only.
 * DOM builders live in components.js; colors/fonts in theme.css; structure in layout.css.
 */

document.addEventListener('DOMContentLoaded', () => {

// ── Config ─────────────────────────────────────────────────────────────────
const WS_URL = 'ws://localhost:8766';

// ── State ──────────────────────────────────────────────────────────────────
let _ws           = null;
let _reconnectMs  = 1500;
let _nodeRefs     = {};       // agentName → { wrap, card, bubble, bubbleText, confFill, badge, sub }
let _treeEl       = null;     // the live #tree div (re-created each run)
let _historyData  = [];
let _runActive    = false;
let _replayMode   = false;
let _activeHistId = null;
let _sentinelNarr = null;     // saved so onDispatch can re-apply after rebuilding the tree
let _sentinelRaw  = null;
let _runTimeout   = null;     // safety: re-enable controls if run_complete never arrives

// ── DOM refs ───────────────────────────────────────────────────────────────
const statusDot   = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');
const treeWrap    = document.getElementById('tree-wrap');
const historyList = document.getElementById('history-list');

// ── WebSocket ──────────────────────────────────────────────────────────────
function connect() {
  _ws = new WebSocket(WS_URL);

  _ws.onopen = () => {
    _reconnectMs = 1500;
    setStatus('connected', 'Connected');
  };

  _ws.onclose = () => {
    setStatus('reconnecting', 'Reconnecting…');
    setTimeout(connect, _reconnectMs);
    _reconnectMs = Math.min(_reconnectMs * 1.5, 10000);
  };

  _ws.onerror = () => {};   // onclose fires after

  _ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    handle(msg);
  };
}

function setStatus(cls, text) {
  statusDot.className = cls;
  statusLabel.textContent = text;
}

// ── Message router ─────────────────────────────────────────────────────────
function handle(msg) {
  const stage = msg.stage;
  const narr  = msg.narration || {};
  const raw   = msg.raw       || {};

  switch (stage) {
    case '__replay__':    onReplay(msg.events || []);        break;
    case 'run_start':     onRunStart(msg);                   break;
    case 'run_complete':  onRunComplete(msg);                break;
    case 'event':         onEvent(narr, raw);               break;
    case 'dispatch':      onDispatch(narr, raw);             break;
    case 'agent_report':  onAgentReport(narr, raw);          break;
    case 'investigator_result': onOrchestratorResult(narr, raw); break;
    case 'policy_result': onPolicy(narr, raw);               break;
    case 'action_record': onAction(narr, raw);               break;
    default: break;
  }
}

// ── Replay ─────────────────────────────────────────────────────────────────
function onReplay(events) {
  _replayMode = true;
  // Preserve the active sidebar highlight — do not reset it during replay.
  const savedHistId = _activeHistId;
  resetTree(true);
  _activeHistId = savedHistId;

  for (const ev of events) {
    if (ev.stage === '__label__') continue;   // skip lifecycle marker
    handle({ ...ev, _replay: true });
  }

  _replayMode = false;
  setControls(true);
}

// ── Run lifecycle ──────────────────────────────────────────────────────────
function onRunStart(msg) {
  _runActive = true;
  setControls(false);
  resetTree(false);

  // Safety timeout: re-enable controls if run_complete never arrives (e.g. backend crash).
  clearTimeout(_runTimeout);
  _runTimeout = setTimeout(() => {
    if (_runActive) {
      _runActive = false;
      setControls(true);
      setStatus('connected', 'Run timed out');
    }
  }, 60000);
}

function onRunComplete(msg) {
  clearTimeout(_runTimeout);
  _runActive = false;
  setControls(true);

  // Pass event_id so _activeHistId is set AFTER the fetch resolves (fixes race condition).
  loadHistory(msg.event_id);

  // Activate the final action node if present.
  const ref = _nodeRefs['action'];
  if (ref) {
    const verdict = _itemVerdict(msg.final_action);
    applyVerdict(ref, verdict, msg.final_action);
    const confFill = ref.confFill;
    if (confFill && msg.confidence) {
      confFill.getBoundingClientRect();
      confFill.style.width = (msg.confidence * 100) + '%';
    }
  }
}

// ── Stage handlers ─────────────────────────────────────────────────────────
function onEvent(narr, raw) {
  // Save narration so onDispatch can re-apply it to the rebuilt sentinel node.
  _sentinelNarr = narr;
  _sentinelRaw  = raw;

  if (!_treeEl) buildTree([]);

  const ref = ensureNode('sentinel');
  activateNode(ref);

  const sub = raw.src_ip || narr.inner_voice || '';
  ref.sub.textContent = sub.length > 40 ? sub.slice(0, 40) + '…' : sub;

  applyNarration(ref, narr, _replayMode);
  scrollBottom();
}

function onDispatch(narr, raw) {
  const parallel   = raw.parallel_agents   || [];
  const sequential = raw.sequential_agents || [];
  const all        = [...parallel, ...sequential];

  buildTree(all, parallel);

  // buildTree creates a fresh sentinel node — re-apply the saved narration
  // so the card keeps its verdict glow and thought bubble.
  const sentRef = _nodeRefs['sentinel'];
  if (sentRef) {
    activateNode(sentRef);
    if (_sentinelNarr) {
      applyNarration(sentRef, _sentinelNarr, _replayMode);
    }
    if (_sentinelRaw?.src_ip) {
      const sub = _sentinelRaw.src_ip;
      sentRef.sub.textContent = sub.length > 40 ? sub.slice(0, 40) + '…' : sub;
    }
  }

  // Apply dispatch narration ("All units, move out.") to the orchestrator node.
  const orchRef = _nodeRefs['orchestrator'];
  if (orchRef && narr && Object.keys(narr).length) {
    applyNarration(orchRef, narr, _replayMode);
  }

  scrollBottom();
}

function onAgentReport(narr, raw) {
  const name = raw.agent_name || narr.agent;
  if (!name) return;

  const ref = _nodeRefs[name];
  if (!ref) return;

  activateNode(ref);
  applyNarration(ref, narr, _replayMode);
  scrollBottom();
}

function onOrchestratorResult(narr, raw) {
  const ref = _nodeRefs['orchestrator'];
  if (!ref) return;

  activateNode(ref);
  applyNarration(ref, narr, _replayMode);
  scrollBottom();
}

function onPolicy(narr, raw) {
  const ref = _nodeRefs['policy'];
  if (!ref) return;

  activateNode(ref);
  applyNarration(ref, narr, _replayMode);
  scrollBottom();
}

function onAction(narr, raw) {
  const ref = _nodeRefs['action'];
  if (!ref) return;

  activateNode(ref);
  if (raw.final_action) {
    const verdict = _itemVerdict(raw.final_action);
    applyVerdict(ref, verdict, raw.final_action);
  }
  if (narr.inner_voice) {
    ref.bubbleText.textContent = narr.inner_voice;
    if (_replayMode) ref.bubble.classList.add('instant');
    ref.bubble.classList.add('open');
  }
  scrollBottom();
}

// ── Tree management ────────────────────────────────────────────────────────
/**
 * Build the tree skeleton for a run.
 * @param {string[]} agentNames  - ordered list (parallel first, then sequential)
 * @param {string[]} parallelSet - subset that runs in parallel
 */
function buildTree(agentNames, parallelSet = []) {
  _nodeRefs  = {};
  _treeEl    = document.createElement('div');
  _treeEl.id = 'tree';

  // Sentinel always first
  if (!agentNames.includes('sentinel')) {
    _appendNode('sentinel');
  }

  // Parallel agents in a row
  const parallelNames = agentNames.filter(n => parallelSet.includes(n));
  const seqNames      = agentNames.filter(n => !parallelSet.includes(n));

  if (parallelNames.length) {
    _appendConnector();
    const row = document.createElement('div');
    row.className = 'parallel-row';
    for (const name of parallelNames) {
      const ref = mkNode(name, { instant: _replayMode });
      _nodeRefs[name] = ref;
      row.appendChild(ref.wrap);
    }
    _treeEl.appendChild(row);
  }

  for (const name of seqNames) {
    _appendConnector();
    _appendNode(name);
  }

  // Always append orchestrator → policy → action at the end if not already in list
  for (const name of ['orchestrator', 'policy', 'action']) {
    if (!agentNames.includes(name)) {
      _appendConnector();
      _appendNode(name);
    }
  }

  treeWrap.innerHTML = '';
  treeWrap.appendChild(_treeEl);
}

function _appendNode(name) {
  if (!_treeEl) return;
  const ref = mkNode(name, { instant: _replayMode });
  _nodeRefs[name] = ref;
  _treeEl.appendChild(ref.wrap);
  return ref;
}

function _appendConnector() {
  if (!_treeEl) return;
  _treeEl.appendChild(mkConnector());
}

/** Get or create a node ref for agentName. */
function ensureNode(name) {
  if (_nodeRefs[name]) return _nodeRefs[name];
  if (!_treeEl) buildTree([]);
  return _appendNode(name);
}

/** Make a node visible (animate in unless instant). */
function activateNode(ref) {
  if (!ref) return;
  if (_replayMode) {
    ref.wrap.classList.add('instant', 'visible');
    return;
  }
  // Use a single rAF so the browser commits the initial state
  // (opacity:0 / translateX) before we add 'visible'.
  // The isConnected guard skips nodes detached by a subsequent resetTree.
  requestAnimationFrame(() => {
    if (ref.wrap.isConnected) {
      ref.wrap.classList.add('visible');
    }
  });
}

function resetTree(instant) {
  _nodeRefs     = {};
  _treeEl       = null;
  _sentinelNarr = null;
  _sentinelRaw  = null;
  treeWrap.innerHTML = '';
  if (!instant) showIdle(true);
}

function showIdle(show) {
  let msg = document.getElementById('idle-msg');
  if (show && !msg) {
    msg = document.createElement('div');
    msg.id = 'idle-msg';
    msg.textContent = 'Waiting for a run…';
    treeWrap.appendChild(msg);
  } else if (!show && msg) {
    msg.remove();
  }
}

function scrollBottom() {
  treeWrap.scrollTop = treeWrap.scrollHeight;
}

// ── History sidebar ────────────────────────────────────────────────────────
/**
 * Fetch history from the server and re-render.
 * @param {string} [afterEventId] - if provided, set as active after fetch resolves
 *   (fixes race: renderHistory() was previously called before fetch completed)
 */
function loadHistory(afterEventId) {
  fetch('/api/history')
    .then(r => r.json())
    .then(data => {
      _historyData = data;
      if (afterEventId) _activeHistId = afterEventId;
      renderHistory();
    })
    .catch(() => {});
}

function renderHistory() {
  historyList.innerHTML = '';
  for (const item of _historyData) {
    const el = mkHistoryItem(item, requestReplay);
    if (item.event_id === _activeHistId) el.classList.add('active');
    historyList.appendChild(el);
  }
}

function requestReplay(eventId) {
  if (!_ws || _ws.readyState !== WebSocket.OPEN) return;
  _activeHistId = eventId;
  renderHistory();
  _ws.send(JSON.stringify({ type: '__request_replay__', event_id: eventId }));
}

// ── Controls ───────────────────────────────────────────────────────────────
function triggerScenario() {
  const scenario = document.getElementById('scenario-select').value;
  post('/api/run', { scenario });
}

function triggerIp() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) return;
  post('/api/run', { ip });
}

function triggerEval() {
  post('/api/evaluate', {});
}

function post(path, body) {
  fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).catch(() => {});
}

function setControls(enabled) {
  document.querySelectorAll('#controls button, #controls input, #controls select').forEach(el => {
    el.disabled = !enabled;
  });
}

// ── Wire up buttons ────────────────────────────────────────────────────────
document.getElementById('btn-run').addEventListener('click', triggerScenario);
document.getElementById('btn-ip').addEventListener('click', triggerIp);
document.getElementById('btn-eval').addEventListener('click', triggerEval);
document.getElementById('ip-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') triggerIp();
});

// ── Boot ───────────────────────────────────────────────────────────────────
showIdle(true);
connect();
loadHistory();

}); // end DOMContentLoaded
