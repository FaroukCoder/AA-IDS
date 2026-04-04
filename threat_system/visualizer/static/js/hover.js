/**
 * hover.js — Left/right hover zones with SVG loading rings.
 *
 * Behaviour:
 *  • Mouse enters zone → ring fill animation begins (2 s)
 *  • Hold 2 s → trigger State.go() for that direction
 *  • Mouse leaves before 2 s → timer cancelled, ring instantly resets
 *  • While a transition is playing → zone clicks are ignored
 */

const Hover = (() => {

  const HOLD_MS = 2000;

  // SVG circumference for r=34: 2π × 34 ≈ 213.63
  const CIRCUMFERENCE = 213.63;

  let _timers = { left: null, right: null };

  // ── Ring helpers ──────────────────────────────────────────────────────────

  function _getRingFill(zoneId) {
    return document.querySelector(`#${zoneId} .ring-fill`);
  }

  function _startFill(zoneId) {
    const fill = _getRingFill(zoneId);
    if (!fill) return;
    // Force reflow so transition plays from dashoffset=CIRCUMFERENCE → 0
    fill.style.transition = 'none';
    fill.style.strokeDashoffset = CIRCUMFERENCE;
    // eslint-disable-next-line no-unused-expressions
    fill.getBoundingClientRect(); // trigger reflow
    fill.classList.add('filling');
  }

  function _resetFill(zoneId) {
    const fill = _getRingFill(zoneId);
    if (!fill) return;
    fill.classList.remove('filling');
    fill.style.transition = 'none';
    fill.style.strokeDashoffset = CIRCUMFERENCE;
    // eslint-disable-next-line no-unused-expressions
    fill.getBoundingClientRect(); // flush so next animation starts clean
  }

  // ── Zone setup ─────────────────────────────────────────────────────────────

  function _bindZone(zoneId, direction) {
    const zone = document.getElementById(zoneId);
    if (!zone) return;

    zone.addEventListener('mouseenter', () => {
      if (VideoManager.isTransitioning()) return;
      if (Cabinet.isOpen()) return;   // panel open — hover navigation disabled
      _startFill(zoneId);
      _timers[direction] = setTimeout(() => {
        _resetFill(zoneId);
        State.go(direction);
      }, HOLD_MS);
    });

    zone.addEventListener('mouseleave', () => {
      clearTimeout(_timers[direction]);
      _timers[direction] = null;
      _resetFill(zoneId);
    });
  }

  // ── Public API ────────────────────────────────────────────────────────────

  function init() {
    _bindZone('hover-left',  'back');
    _bindZone('hover-right', 'forward');
  }

  /**
   * Show/hide zones based on which scene is active.
   *  • D1: left zone hidden (no scene behind D1)
   *  • D3: right zone hidden (no scene ahead of D3)
   *  • Investigation: both zones hidden
   */
  function updateForScene(scene) {
    const left  = document.getElementById('hover-left');
    const right = document.getElementById('hover-right');
    if (!left || !right) return;

    const hideLeft  = (scene === 'd1' || scene === 'investigation');
    const hideRight = (scene === 'd3' || scene === 'investigation');

    left.classList.toggle('hidden',  hideLeft);
    right.classList.toggle('hidden', hideRight);

    // Cancel any in-progress timers when scene changes
    clearTimeout(_timers.back);
    clearTimeout(_timers.forward);
    _resetFill('hover-left');
    _resetFill('hover-right');
  }

  return { init, updateForScene };

})();
