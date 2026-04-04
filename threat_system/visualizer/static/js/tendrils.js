/**
 * tendrils.js — Canvas neural tendril renderer (stub).
 * Full implementation deferred to a later phase.
 */

const Tendrils = (() => {

  function init() {
    const canvas = document.getElementById('tendrils-canvas');
    if (!canvas) return;
    // Keep canvas sized to viewport
    function resize() {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);
  }

  return { init };

})();
