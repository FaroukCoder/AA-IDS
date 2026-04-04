/**
 * video-manager.js — All video playback logic for the Detective UI.
 *
 * Manages:
 *  • Scene loop videos (crossfade pair: loop-video-a / loop-video-b)
 *  • D1 idle variations (random pick every 30–60s)
 *  • Transition videos between scenes
 *  • Graceful fallback to static PNG on any video error
 */

const VideoManager = (() => {

  // ── Asset paths ───────────────────────────────────────────────────────────
  // NOTE: folder names contain spaces → must be %20 encoded.
  const LOOPS = {
    d1: [
      'assets/videos/detective%201/d1_idle_main.mp4',
      'assets/videos/detective%201/d1_idle_var1.mp4',
      'assets/videos/detective%201/d1_idle_var2.mp4',
      'assets/videos/detective%201/d1_idle_var3.mp4',
      'assets/videos/detective%201/d1_idle_var4.mp4',
    ],
    d2: ['assets/videos/detective%202/d2_loop.mp4'],
    d3: ['assets/videos/detective%203/d3_loop.mp4'],
    investigation: [], // deferred — no video yet
  };

  const TRANSITIONS = {
    'd1→d2': 'assets/videos/transitions/d1_to_d2.mp4',
    'd2→d1': 'assets/videos/transitions/d2_to_d1.mp4',
    'd2→d3': 'assets/videos/transitions/d2_to_d3.mp4',
    'd3→d2': 'assets/videos/transitions/d3_to_d2.mp4',
    'd1→inv': null,  // deferred
    'inv→d1': null,  // deferred
  };

  // Static fallback images per scene
  const STATIC_PNG = {
    d1: 'assets/detective_1.png',
    d2: 'assets/detective_2.png',
    d3: 'assets/detective_3.png',
    investigation: 'assets/detective_1.png',
  };

  // ── DOM refs (resolved after DOMContentLoaded) ────────────────────────────
  let loopA, loopB, transVideo, staticBg;
  let _activeIsA = true;
  let _transitioning = false;
  let _idleTimer = null;
  let _currentScene = 'd1';

  // ── Private helpers ───────────────────────────────────────────────────────

  function activeLoop()   { return _activeIsA ? loopA : loopB; }
  function inactiveLoop() { return _activeIsA ? loopB : loopA; }

  function _showStaticFallback(scene) {
    const s = scene || _currentScene;
    staticBg.src = STATIC_PNG[s] || STATIC_PNG.d1;
    staticBg.style.opacity = '1';
    loopA.style.opacity = '0';
    loopB.style.opacity = '0';
  }

  function _safePlay(video) {
    const p = video.play();
    if (p && typeof p.catch === 'function') {
      p.catch(() => _showStaticFallback());
    }
  }

  function _scheduleIdleVariation() {
    clearTimeout(_idleTimer);
    if (_currentScene !== 'd1') return;

    const delayMs = (30 + Math.random() * 30) * 1000; // 30–60s
    _idleTimer = setTimeout(_playIdleVariation, delayMs);
  }

  function _playIdleVariation() {
    if (_currentScene !== 'd1' || _transitioning) return;

    // Pick a random variation (indices 1–4, skip index 0 which is main)
    const vars = LOOPS.d1.slice(1);
    const src = vars[Math.floor(Math.random() * vars.length)];

    const idle = inactiveLoop();
    idle.src = src;
    idle.loop = false;
    idle.style.transition = 'opacity 0.8s ease';

    idle.onended = () => {
      // Crossfade back to main loop
      const main = activeLoop();
      main.src = LOOPS.d1[0];
      main.loop = true;
      main.style.transition = 'opacity 0.8s ease';

      _safePlay(main);
      main.style.opacity = '1';
      idle.style.opacity = '0';
      idle.onended = null;

      _activeIsA = !_activeIsA; // swap back conceptually — actually main is now active
      // Re-schedule next variation
      _scheduleIdleVariation();
    };

    idle.onerror = () => {
      idle.onended = null;
      _scheduleIdleVariation();
    };

    _safePlay(idle);

    // Crossfade: bring idle up, push current main down
    idle.style.opacity = '1';
    activeLoop().style.opacity = '0';
  }

  // ── Public API ────────────────────────────────────────────────────────────

  function preload() {
    loopA     = document.getElementById('loop-video-a');
    loopB     = document.getElementById('loop-video-b');
    transVideo = document.getElementById('transition-video');
    staticBg  = document.getElementById('static-bg');

    // Eagerly create hidden video elements to prime the browser cache
    const allSrcs = [
      ...Object.values(LOOPS).flat(),
      ...Object.values(TRANSITIONS).filter(Boolean),
    ];

    allSrcs.forEach(src => {
      const v = document.createElement('video');
      v.src = src;
      v.preload = 'auto';
      v.style.display = 'none';
      // Remove immediately after metadata loads — we just want the browser to cache it
      v.onloadedmetadata = () => v.remove();
      v.onerror = () => v.remove();
      document.body.appendChild(v);
    });
  }

  /**
   * Start looping the scene's main video.
   * @param {string} scene  — 'd1' | 'd2' | 'd3' | 'investigation'
   */
  function playLoop(scene) {
    _currentScene = scene;
    clearTimeout(_idleTimer);

    const srcs = LOOPS[scene];
    if (!srcs || srcs.length === 0) {
      _showStaticFallback(scene);
      return;
    }

    const vid = activeLoop();
    vid.src = srcs[0];
    vid.loop = true;
    vid.style.transition = 'opacity 0.5s ease';
    vid.style.opacity = '1';
    inactiveLoop().style.opacity = '0';
    staticBg.style.opacity = '0';

    vid.onerror = () => _showStaticFallback(scene);
    _safePlay(vid);

    if (scene === 'd1') {
      _scheduleIdleVariation();
    }
  }

  /**
   * Play a transition video then call onComplete().
   * If the transition src is null, onComplete() fires immediately.
   * @param {string}   key         — e.g. 'd1→d2'
   * @param {Function} onComplete  — called when transition ends (or immediately if null)
   */
  function playTransition(key, onComplete) {
    const src = TRANSITIONS[key] ?? null;

    if (!src) {
      onComplete();
      return;
    }

    _transitioning = true;
    clearTimeout(_idleTimer);

    transVideo.src = src;
    transVideo.loop = false;
    transVideo.style.transition = 'opacity 0.25s ease';

    const finish = () => {
      transVideo.style.opacity = '0';
      transVideo.onended = null;
      transVideo.onerror = null;
      _transitioning = false;
      onComplete();
    };

    transVideo.onended = finish;
    transVideo.onerror = () => {
      _showStaticFallback();
      finish();
    };

    transVideo.style.opacity = '1';
    _safePlay(transVideo);
  }

  /** Returns true while a transition is playing — used by hover.js to block double-trigger. */
  function isTransitioning() {
    return _transitioning;
  }

  /** No-op: investigation video not yet available. */
  function flagInvestigationComplete() {
    console.warn('[VideoManager] flagInvestigationComplete — investigation video deferred');
  }

  return { preload, playLoop, playTransition, isTransitioning, flagInvestigationComplete };

})();
