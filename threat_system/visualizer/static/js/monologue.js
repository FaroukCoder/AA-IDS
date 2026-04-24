/**
 * monologue.js — Detective narration panel renderer.
 *
 * Full-height left panel visible during any active investigation (D1 scene).
 * Controlled exclusively by websocket.js — shown on run_start, hidden on run_complete.
 *
 * Public API
 * ----------
 * Monologue.show(eventId)           — make panel visible, set run ID in header
 * Monologue.hide()                  — hide panel
 * Monologue.clear()                 — empty entries + reset queue
 * Monologue.add(voice, text, conf)  — enqueue a narration line
 */

const Monologue = (() => {

  const TYPE_SPEED  = 28;   // ms per character
  const ENTRY_GAP   = 320;  // ms pause between queued entries

  // ── Voice → colour + portrait image mapping ────────────────────────────────
  // Keys must match the voice strings passed by websocket.js VOICE_NAMES
  const VOICES = {
    'SHIVERS':       { color: '#89dceb', img: 'shivers'       },
    'VISUAL CORTEX': { color: '#f9e2af', img: 'visual_cortex' },
    'AUDITORY':      { color: '#9b7fd4', img: 'auditory'      },
    'MEMORY':        { color: '#c87941', img: 'memory'        },
    'LOGIC CENTER':  { color: '#7fb0a0', img: 'logic_center'  },
    'THE RULEBOOK':  { color: '#8faa6b', img: 'rulebook'      },
    '—':             { color: '#6b5a3a', img: null             },
  };

  // ── Organic brushstroke outline paths (one per portrait) ──────────────────
  // Each path is sized to a 96×96 viewBox coordinate space
  const BRUSH_PATHS = {
    shivers:       'M54,10 C68,8 82,18 86,32 C90,46 85,62 78,72 C68,84 50,90 36,88 C20,86 8,74 6,60 C2,44 8,26 20,16 C30,8 42,12 54,10Z',
    visual_cortex: 'M56,8 C72,6 86,20 88,36 C90,50 82,66 70,74 C56,84 38,86 24,78 C10,70 4,54 6,38 C8,22 22,10 38,8 C44,6 50,8 56,8Z',
    auditory:      'M50,6 C66,4 82,16 88,32 C94,48 88,66 76,76 C62,88 42,90 28,82 C12,72 4,54 6,36 C8,20 22,8 38,6 C42,4 46,6 50,6Z',
    memory:        'M52,8 C68,6 84,18 88,34 C92,50 86,68 72,78 C58,88 38,90 24,80 C8,70 2,52 6,34 C10,18 26,8 42,8 C46,7 50,8 52,8Z',
    logic_center:  'M54,10 C70,8 84,20 86,36 C88,52 80,68 66,76 C52,86 34,86 20,76 C6,66 2,48 6,32 C10,18 24,8 40,8 C46,7 50,10 54,10Z',
    rulebook:      'M50,8 C66,6 82,18 86,34 C90,52 84,70 70,80 C56,90 36,90 22,80 C8,68 2,50 6,32 C10,16 24,6 40,6 C44,6 48,8 50,8Z',
  };

  let _queue     = [];
  let _typing    = false;
  let _idCounter = 0;

  const _panel    = () => document.getElementById('monologue-panel');
  const _scroll   = () => document.getElementById('monologue-scroll');
  const _entries  = () => document.getElementById('monologue-entries');
  const _runIdEl  = () => document.getElementById('monologue-run-id');

  // ── Brushstroke portrait SVG ───────────────────────────────────────────────

  function _makePortrait(imgKey, size) {
    size = size || 88;
    if (!imgKey || !BRUSH_PATHS[imgKey]) {
      return '<div class="mono-portrait-wrap" style="width:' + size + 'px;height:' + size + 'px;"></div>';
    }

    const path = BRUSH_PATHS[imgKey];
    const src  = 'assets/agents/' + imgKey + '.png';
    const fid  = 'mf_' + imgKey + '_' + _idCounter;
    const mid  = 'mm_' + imgKey + '_' + _idCounter;

    // Slightly zoom the image so it fills the brushstroke shape
    const zoom = 1.18;
    const sw   = (size * zoom).toFixed(0);
    const sh   = (size * zoom).toFixed(0);
    const ox   = (-(size * zoom - size) * 0.5).toFixed(1);
    const oy   = (-(size * zoom - size) * 0.25).toFixed(1);

    return [
      '<div class="mono-portrait-wrap">',
      '  <svg width="' + size + '" height="' + size + '"',
      '       viewBox="0 0 96 96" style="overflow:visible;">',
      '    <defs>',
      '      <filter id="' + fid + '" x="-20%" y="-20%" width="140%" height="140%">',
      '        <feGaussianBlur stdDeviation="4"/>',
      '      </filter>',
      '      <mask id="' + mid + '">',
      '        <path d="' + path + '" fill="white" filter="url(#' + fid + ')"/>',
      '      </mask>',
      '    </defs>',
      '    <image href="' + src + '"',
      '           x="' + ox + '" y="' + oy + '"',
      '           width="' + sw + '" height="' + sh + '"',
      '           preserveAspectRatio="xMidYMid slice"',
      '           mask="url(#' + mid + ')"/>',
      '  </svg>',
      '</div>',
    ].join('\n');
  }

  // ── Typewriter ─────────────────────────────────────────────────────────────

  function _typeInto(el, text, onDone) {
    el.innerHTML = '';
    const cursor = document.createElement('span');
    cursor.className = 'mono-cursor';
    el.appendChild(cursor);
    let i = 0;

    function step() {
      if (i < text.length) {
        el.insertBefore(document.createTextNode(text[i++]), cursor);
        const s = _scroll();
        if (s) s.scrollTop = s.scrollHeight;
        setTimeout(step, TYPE_SPEED);
      } else {
        cursor.remove();
        if (onDone) onDone();
      }
    }
    setTimeout(step, TYPE_SPEED);
  }

  // ── Build a single entry element ───────────────────────────────────────────

  function _buildEntry(voice, text, conf) {
    _idCounter++;
    const vcfg   = VOICES[voice] || VOICES['—'];
    const color  = vcfg.color;
    const imgKey = vcfg.img;
    const isNarr = (voice === '—');

    const entry = document.createElement('div');
    entry.className = isNarr ? 'mono-entry narrator' : 'mono-entry';

    if (isNarr) {
      entry.innerHTML = '<span class="mono-text" data-typing></span>';
    } else {
      const confHtml = (conf !== null && conf !== undefined)
        ? [
            '<div class="mono-conf-row">',
            '  <div class="mono-conf-bg">',
            '    <div class="mono-conf-fill"',
            '         style="background:' + color + ';"',
            '         data-target="' + Math.round(conf * 100) + '"></div>',
            '  </div>',
            '  <span class="mono-conf-num">' + Math.round(conf * 100) + '%</span>',
            '</div>',
          ].join('\n')
        : '';

      entry.innerHTML = [
        _makePortrait(imgKey),
        '<div class="mono-body">',
        '  <div class="mono-name-row">',
        '    <div class="mono-bar" style="background:' + color + ';"></div>',
        '    <span class="mono-name" style="color:' + color + ';">' + _esc(voice) + '</span>',
        '  </div>',
        '  <span class="mono-text" data-typing></span>',
        confHtml,
        '</div>',
      ].join('\n');
    }

    return entry;
  }

  // ── Process the queue one entry at a time ──────────────────────────────────

  function _processQueue() {
    if (_typing || _queue.length === 0) return;
    _typing = true;

    const item = _queue.shift();
    const entry  = _buildEntry(item.voice, item.text, item.conf);
    const el     = _entries();
    if (!el) { _typing = false; return; }

    el.appendChild(entry);
    // Entry fades in via @keyframes mono-entry-in — no class flip needed.

    // Scroll to bottom
    const s = _scroll();
    if (s) setTimeout(function() { s.scrollTop = s.scrollHeight; }, 50);

    // Type out the text
    const textEl = entry.querySelector('[data-typing]');
    if (!textEl) {
      // Guard: malformed entry — skip gracefully so queue never deadlocks
      _typing = false;
      setTimeout(_processQueue, ENTRY_GAP);
      return;
    }
    _typeInto(textEl, item.text, function() {
      // Animate confidence bar after typing
      const fill = entry.querySelector('.mono-conf-fill');
      if (fill && fill.dataset.target) {
        setTimeout(function() {
          fill.style.width = fill.dataset.target + '%';
        }, 80);
      }
      _typing = false;
      setTimeout(_processQueue, ENTRY_GAP);
    });
  }

  // ── Final verdict box ─────────────────────────────────────────────────────

  /**
   * Append a styled verdict summary box (no typewriter — instant render).
   * @param {object} data  — run_complete message: { classification, confidence, final_action }
   */
  function addVerdict(data) {
    // Wait until the typing queue is fully drained before appending, so the
    // verdict always lands at the bottom of the conversation.
    function _tryAppend() {
      if (_typing || _queue.length > 0) {
        setTimeout(_tryAppend, ENTRY_GAP);
        return;
      }
      const el = _entries();
      if (!el) return;

      const cls    = String(data.classification || 'unknown').toLowerCase();
      const conf   = typeof data.confidence === 'number'
                     ? Math.round(data.confidence * 100) + '%' : '—';
      const action = String(data.final_action || data.recommended_action || '')
                     .replace(/_/g, ' ');

      const colorClass = cls === 'malicious' ? 'malicious'
                       : cls === 'suspicious' ? 'suspicious'
                       : cls === 'benign'     ? 'benign'
                       : '';

      const div = document.createElement('div');
      div.className = 'mono-verdict' + (colorClass ? ' ' + colorClass : '');
      div.innerHTML = [
        '<div class="mono-verdict-label">Final Verdict</div>',
        '<div class="mono-verdict-cls">' + _esc(cls.toUpperCase()) + '</div>',
        '<div class="mono-verdict-detail">' + _esc(conf) + ' confidence &nbsp;·&nbsp; ' + _esc(action) + '</div>',
      ].join('');
      el.appendChild(div);

      const s = _scroll();
      if (s) setTimeout(function() { s.scrollTop = s.scrollHeight; }, 50);
    }
    _tryAppend();
  }

  // ── Separator between consecutive burst runs ───────────────────────────────

  function addSeparator(label) {
    const el = _entries();
    if (!el || el.children.length === 0) return;
    const div = document.createElement('div');
    div.className = 'mono-separator';
    div.textContent = label || '·';
    el.appendChild(div);
    const s = _scroll();
    if (s) setTimeout(function() { s.scrollTop = s.scrollHeight; }, 50);
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Show the panel. Pass the run's event_id to display it in the header.
   * @param {string} [eventId]
   */
  function show(eventId) {
    const p = _panel();
    if (p) p.classList.add('active');
    const rid = _runIdEl();
    if (rid) rid.textContent = eventId || '';
  }

  /** Hide the panel. */
  function hide() {
    const p = _panel();
    if (p) p.classList.remove('active');
  }

  /**
   * Clear all entries and reset the queue.
   * Call before a new run starts.
   */
  function clear() {
    _queue     = [];
    _typing    = false;
    _idCounter = 0;
    const el = _entries();
    if (el) el.innerHTML = '';
    const rid = _runIdEl();
    if (rid) rid.textContent = '';
  }

  /**
   * Enqueue a narration line. Renders in order with typewriter effect.
   * @param {string}      voice  — display name (e.g. 'MEMORY', '—')
   * @param {string}      text   — the inner voice text
   * @param {number|null} conf   — 0–1 confidence, or null to omit bar
   */
  function add(voice, text, conf) {
    if (!text) return;
    _queue.push({ voice: voice || '—', text: text, conf: conf });
    _processQueue();
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function _esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return { show, hide, clear, add, addVerdict, addSeparator };

})();
