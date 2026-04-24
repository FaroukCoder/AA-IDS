/**
 * websocket.js — Live pipeline WebSocket client.
 *
 * Connects to ws://localhost:8766, routes incoming stage events to the right
 * UI modules, and auto-reconnects when the server restarts.
 *
 * Public API
 * ----------
 * WS.connect()               — called once at page load
 * WS.requestReplay(eventId)  — ask server for a full run trace by event_id
 *
 * Shared state
 * ------------
 * window._runActive (read-only getter) — true while a run is live;
 * read by state.js to guard Agents.reset() during scene transitions.
 */

const WS = (() => {

  const WS_URL       = 'ws://localhost:8766';
  const RECONNECT_MS = 3000;

  let _ws                  = null;
  let _reconnectTimer      = null;
  let _runActive           = false;
  let _lastRunCompleteTime = 0;   // epoch ms of most recent run_complete
  let _verdictTimer        = null; // debounce: show verdict only after last run in a burst

  // Expose as a read-only window property so state.js can read it without
  // creating a circular dependency between modules.
  Object.defineProperty(window, '_runActive', {
    get: () => _runActive,
    configurable: true,
  });

  // ── Voice display names ────────────────────────────────────────────────────
  const VOICE_NAMES = {
    shivers:      'SHIVERS',
    whois:        'VISUAL CORTEX',
    dns:          'AUDITORY',
    reputation:   'MEMORY',
    port_intel:   'LOGIC CENTER',
    policy:       'THE RULEBOOK',
    orchestrator: '—',
  };

  // ── Connection ─────────────────────────────────────────────────────────────

  function connect() {
    clearTimeout(_reconnectTimer);
    try {
      _ws = new WebSocket(WS_URL);
    } catch {
      _scheduleReconnect();
      return;
    }

    _ws.onopen = () => {
      clearTimeout(_reconnectTimer);
      // Refresh cards on every (re)connect so runs that completed while the
      // browser was disconnected appear immediately.
      Cabinet.loadHistory();
    };

    _ws.onclose = () => {
      _ws = null;
      _scheduleReconnect();
    };

    _ws.onerror = () => {
      // onclose fires after onerror; reconnect handled there
    };

    _ws.onmessage = (evt) => {
      let msg;
      try { msg = JSON.parse(evt.data); } catch { return; }
      _dispatch(msg);
    };
  }

  function _scheduleReconnect() {
    _reconnectTimer = setTimeout(connect, RECONNECT_MS);
  }

  // ── Message dispatch ───────────────────────────────────────────────────────

  function _dispatch(msg) {
    const type = msg.type  || msg.stage || '';
    const raw  = msg.raw   || {};         // pipeline events embed data under "raw"
    const narr = msg.narration || {};     // narration object from the narrator

    switch (type) {

      // Full run trace — hydrate the detail view if it's currently open
      case '__replay__':
        Cabinet.hydrateDetail(msg.events || []);
        break;

      // New run starting — show monologue, reset agents
      // ws_server.py broadcasts: {"stage":"run_start","label":"live_NNNN"}
      case 'run_start': {
        const isConsecutive = (Date.now() - _lastRunCompleteTime) < 15000;
        _runActive = true;
        Agents.reset();
        clearTimeout(_verdictTimer);   // cancel pending verdict — burst continues
        if (isConsecutive) {
          Monologue.addSeparator(msg.label || '');   // keep history, add divider
        } else {
          Monologue.clear();                         // fresh attack — start clean
        }
        Monologue.show(msg.label || msg.event_id || '');
        break;
      }

      // Orchestrator dispatched agents — scaffold portraits, open monologue.
      // orchestrator.py sends SimpleNamespace(parallel_agents=[...], sequential_agents=[...])
      // which _to_dict() serialises into raw.parallel_agents / raw.sequential_agents.
      case 'dispatch': {
        const parallel   = Array.isArray(raw.parallel_agents)   ? raw.parallel_agents   : [];
        const sequential = Array.isArray(raw.sequential_agents) ? raw.sequential_agents : [];
        const agentList  = parallel.concat(sequential);
        if (agentList.length) Agents.scaffold(agentList);
        // narrate_dispatch always returns an inner_voice
        const dispatchLine = narr.inner_voice || narr.text || '\u201cAll units, move out.\u201d';
        Monologue.add('—', dispatchLine, null);
        break;
      }

      // Individual agent finished — summon portrait, log inner voice.
      // raw = AgentReport dataclass: {agent_name, findings, confidence, error, fallback}
      // narr = narrator.narrate_agent result: {agent, inner_voice, confidence, ...}
      case 'agent_report': {
        const agentKey = raw.agent_name || '';
        const voice    = VOICE_NAMES[agentKey] || agentKey.replace(/_/g, ' ').toUpperCase();
        const line     = narr.inner_voice || narr.text || '';
        const conf     = typeof narr.confidence === 'number' ? narr.confidence
                       : typeof raw.confidence  === 'number' ? raw.confidence
                       : null;
        if (agentKey) Agents.summon(agentKey);
        if (line)     Monologue.add(voice, line, conf);
        setTimeout(() => { if (agentKey) Agents.complete(agentKey); }, 2200);
        break;
      }

      // Investigator overall verdict.
      // narr = narrator.narrate_orchestrator: {inner_voice, confidence, ...}
      case 'investigator_result': {
        const line = narr.inner_voice || narr.text || '';
        const conf = typeof narr.confidence === 'number' ? narr.confidence
                   : typeof raw.confidence  === 'number' ? raw.confidence
                   : null;
        if (line) Monologue.add('—', line, conf);
        break;
      }

      // Policy decision.
      // narr = narrator.narrate_policy: {inner_voice, ...}
      case 'policy_result': {
        const line = narr.inner_voice || narr.text || '';
        if (line) Monologue.add('THE RULEBOOK', line, null);
        break;
      }

      // Run finished — add cabinet card, then clean up after 4 s
      case 'run_complete': {
        _runActive = false;
        _lastRunCompleteTime = Date.now();
        // run_complete fields are broadcast at top level (not nested under raw/data)
        if (msg.event_id && msg.classification) {
          Cabinet.addLiveRun(msg);
        }
        Agents.reset();
        if (typeof Tendrils !== 'undefined' && typeof Tendrils.resetAll === 'function') {
          Tendrils.resetAll();
        }
        // Debounced verdict: wait 6 s after the LAST run_complete in a burst.
        // If a new run_start arrives it cancels this timer, so the verdict
        // only appears once all sub-runs are done.
        const _verdictMsg = msg;
        clearTimeout(_verdictTimer);
        _verdictTimer = setTimeout(() => {
          if (!_runActive) Monologue.addVerdict(_verdictMsg);
        }, 6000);
        // Panel stays visible until user clicks ×
        break;
      }

      // Sentinel raw event — narrate if narration present
      case 'event':
        if (narr.text || narr.inner_voice) {
          Monologue.add('—', narr.text || narr.inner_voice, null);
        }
        break;
    }
  }

  // ── Public helpers ─────────────────────────────────────────────────────────

  /**
   * Ask the server to replay a specific past run.
   * The response arrives as a '__replay__' message and is handled by _dispatch.
   */
  function requestReplay(eventId) {
    if (_ws && _ws.readyState === WebSocket.OPEN) {
      _ws.send(JSON.stringify({ type: '__request_replay__', event_id: eventId }));
    }
  }

  return { connect, requestReplay };

})();
