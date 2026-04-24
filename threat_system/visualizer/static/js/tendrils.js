/**
 * tendrils.js — Canvas neural tendril renderer (stub).
 * Full visual implementation deferred to a later phase.
 * All methods are safe no-ops so callers (agents.js, websocket.js) don't crash.
 */

const Tendrils = (() => {

  function init() {
    const canvas = document.getElementById('tendrils-canvas');
    if (!canvas) return;
    function resize() {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);
  }

  /** Draw a tendril from BRAIN_ANCHOR to the agent's portrait position. */
  function draw(agentName, cfg) {
    // stub — visual implementation deferred
  }

  /** Reduce opacity of a named tendril (agent complete). */
  function dim(agentName) {
    // stub — visual implementation deferred
  }

  /** Fade all tendrils then clear the canvas (run complete / scene change). */
  function resetAll() {
    const canvas = document.getElementById('tendrils-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
  }

  return { init, draw, dim, resetAll };

})();
