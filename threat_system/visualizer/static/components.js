/**
 * components.js — Pure DOM builder functions. No state, no WS, no API calls.
 *
 * To change card design or bubble style: edit this file only.
 * To change colors/icons: edit AGENT_CONFIG or theme.css vars.
 */

// ── Agent configuration (single source of truth) ──────────────────────────
const AGENT_CONFIG = {
  sentinel:     { color: 'var(--c-sentinel)',     icon: '🛡️', label: 'SENTINEL'     },
  whois:        { color: 'var(--c-whois)',         icon: '🔍', label: 'WHOIS'        },
  dns:          { color: 'var(--c-dns)',           icon: '📡', label: 'DNS'          },
  port_intel:   { color: 'var(--c-port-intel)',    icon: '⚔️', label: 'PORT INTEL'   },
  reputation:   { color: 'var(--c-reputation)',    icon: '🎯', label: 'REPUTATION'   },
  orchestrator: { color: 'var(--c-orchestrator)',  icon: '🧠', label: 'ORCHESTRATOR' },
  policy:       { color: 'var(--c-policy)',        icon: '⚖️', label: 'POLICY'       },
  action:       { color: 'var(--c-action)',        icon: '🔒', label: 'FINAL ACTION' },
};

// ── Verdict → CSS var mappings ─────────────────────────────────────────────
const VERDICT_COLOR = {
  clean:      'var(--v-clean)',
  suspicious: 'var(--v-suspicious)',
  malicious:  'var(--v-malicious)',
  escalated:  'var(--v-escalated)',
  pending:    'var(--v-pending)',
  unknown:    'var(--v-unknown)',
};

const VERDICT_GLOW = {
  clean:      'var(--glow-clean)',
  suspicious: 'var(--glow-suspicious)',
  malicious:  'var(--glow-malicious)',
  escalated:  'var(--glow-escalated)',
};

// ── mkNode ─────────────────────────────────────────────────────────────────
/**
 * Create a node-wrap + node-card + bubble-wrap for a given agent.
 * Returns { wrap, card, bubble, confFill, badge, sub } — all DOM elements.
 *
 * @param {string} agentName  - key into AGENT_CONFIG
 * @param {object} [opts]
 * @param {boolean} [opts.instant] - skip entry animation (replay mode)
 */
function mkNode(agentName, opts = {}) {
  const cfg = AGENT_CONFIG[agentName] || { color: 'var(--text)', icon: '?', label: agentName.toUpperCase() };

  // ── outer wrap (handles enter animation) ────────────────────────────────
  const wrap = document.createElement('div');
  wrap.className = 'node-wrap';
  if (opts.instant) wrap.classList.add('instant');

  // ── card ─────────────────────────────────────────────────────────────────
  const card = document.createElement('div');
  card.className = 'node-card';

  const icon = document.createElement('div');
  icon.className = 'node-icon';
  icon.textContent = cfg.icon;

  const header = document.createElement('div');
  header.className = 'node-header';

  const labelEl = document.createElement('div');
  labelEl.className = 'node-label';
  labelEl.style.color = cfg.color;
  labelEl.textContent = cfg.label;

  const sub = document.createElement('div');
  sub.className = 'node-sub';

  const badge = document.createElement('div');
  badge.className = 'verdict-badge';
  badge.textContent = 'PENDING';

  const confTrack = document.createElement('div');
  confTrack.className = 'conf-track';

  const confFill = document.createElement('div');
  confFill.className = 'conf-fill';
  confFill.style.background = cfg.color;
  confTrack.appendChild(confFill);

  header.append(labelEl, sub, badge, confTrack);
  card.append(icon, header);

  // ── bubble ───────────────────────────────────────────────────────────────
  const bubbleWrap = document.createElement('div');
  bubbleWrap.className = 'bubble-wrap';
  if (opts.instant) bubbleWrap.classList.add('instant');

  const bubble = document.createElement('div');
  bubble.className = 'bubble';

  const bubbleText = document.createElement('div');
  bubbleText.className = 'bubble-text';
  bubble.appendChild(bubbleText);
  bubbleWrap.appendChild(bubble);

  wrap.append(card, bubbleWrap);

  return { wrap, card, bubble: bubbleWrap, bubbleText, confFill, badge, sub };
}

// ── mkConnector ────────────────────────────────────────────────────────────
/** Vertical line between tree nodes. */
function mkConnector() {
  const el = document.createElement('div');
  el.className = 'connector';
  return el;
}

// ── mkHistoryItem ──────────────────────────────────────────────────────────
/**
 * Build a sidebar history entry.
 * @param {object} item  - { event_id, target, final_action, classification, confidence }
 * @param {function} onClick
 */
function mkHistoryItem(item, onClick) {
  const el = document.createElement('div');
  el.className = 'hist-item';
  el.dataset.eventId = item.event_id;

  const verdict = _itemVerdict(item.final_action);
  const color   = VERDICT_COLOR[verdict] || 'var(--v-unknown)';
  const pct     = Math.round((item.confidence || 0) * 100);

  el.innerHTML = `
    <div class="hi-id">${_esc(item.event_id)}</div>
    <div class="hi-meta">${_esc(item.target || '—')}</div>
    <div class="verdict-badge hi-verdict" style="color:${color};border:1px solid ${color}22">${_esc(item.final_action || '?')} ${pct ? pct + '%' : ''}</div>
  `;
  el.addEventListener('click', () => onClick(item.event_id));
  return el;
}

// ── applyVerdict ───────────────────────────────────────────────────────────
/**
 * Update a node's visual state to reflect a verdict.
 * @param {{ card, badge, sub }} nodeRef - from mkNode()
 * @param {string} verdict - 'clean' | 'suspicious' | 'malicious' | 'escalated' | 'unknown'
 * @param {string} [label] - override badge text
 */
function applyVerdict(nodeRef, verdict, label) {
  const color = VERDICT_COLOR[verdict] || 'var(--v-unknown)';
  const glow  = VERDICT_GLOW[verdict];

  nodeRef.badge.textContent = label || verdict.toUpperCase();
  nodeRef.badge.style.color       = color;
  nodeRef.badge.style.borderColor = color + '44';
  if (glow) nodeRef.card.style.boxShadow = glow;
  nodeRef.card.style.borderColor = color + '55';
}

// ── applyNarration ─────────────────────────────────────────────────────────
/**
 * Fill a node's thought bubble and confidence bar from a narration object.
 * @param {{ bubble, bubbleText, confFill, badge, sub, card }} nodeRef
 * @param {object} narration - { inner_voice, verdict, confidence, catchphrase }
 * @param {boolean} [instant] - skip transitions (replay mode)
 */
function applyNarration(nodeRef, narration, instant) {
  if (!narration) return;

  const { inner_voice, verdict, confidence, catchphrase } = narration;

  // Sub-label (catchphrase)
  if (catchphrase) nodeRef.sub.textContent = catchphrase;

  // Thought bubble
  if (inner_voice) {
    nodeRef.bubbleText.textContent = inner_voice;
    if (instant) {
      nodeRef.bubble.classList.add('instant');
    }
    nodeRef.bubble.classList.add('open');
  }

  // Verdict
  if (verdict) applyVerdict(nodeRef, verdict);

  // Confidence bar
  if (typeof confidence === 'number' && confidence > 0) {
    if (instant) {
      nodeRef.confFill.style.transition = 'none';
      nodeRef.confFill.style.width = (confidence * 100) + '%';
    } else {
      // Delay 100ms so the bar starts filling AFTER the node has begun fading in,
      // making the animation visible rather than already-complete on entry.
      setTimeout(() => {
        nodeRef.confFill.style.width = '0';           // reset to 0 first (fixes repeat-run animation)
        nodeRef.confFill.getBoundingClientRect();      // force reflow at 0
        nodeRef.confFill.style.width = (confidence * 100) + '%';
      }, 100);
    }
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
function _esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function _itemVerdict(finalAction) {
  if (!finalAction) return 'unknown';
  if (finalAction === 'block_ip')      return 'malicious';
  if (finalAction === 'alert_admin')   return 'suspicious';
  if (finalAction === 'escalate_human') return 'escalated';
  if (finalAction === 'log_only')      return 'clean';
  return 'unknown';
}
