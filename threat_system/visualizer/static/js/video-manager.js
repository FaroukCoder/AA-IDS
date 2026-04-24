/**
 * video-manager.js — All video playback logic for the Detective UI.
 *
 * Manages:
 *  • Scene loop videos (crossfade pair: loop-video-a / loop-video-b)
 *  • D1 idle variations (random pick every 3–12 loops of the main video)
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
  let _idleLoopCleanup = null;    // fn() that removes the timeupdate listener
  let _currentScene = 'd1';

  // ── Private helpers ───────────────────────────────────────────────────────

  function activeLoop()   { return _activeIsA ? loopA : loopB; }
  function inactiveLoop() { return _activeIsA ? loopB : loopA; }

  function _showStaticFallback(scene) {
    const s = scene || _currentScene;
    staticBg.src = STATIC_PNG[s] || STATIC_PNG.d1;
    staticBg.style.transition = 'none';
    staticBg.style.opacity = '1';
    loopA.style.transition = 'none';
    loopA.style.opacity = '0';
    loopB.style.transition = 'none';
    loopB.style.opacity = '0';
  }

  function _safePlay(video) {
    const p = video.play();
    if (p && typeof p.catch === 'function') {
      p.catch(() => _showStaticFallback());
    }
  }

  /** Cancel any pending idle variation — removes timeupdate listener + clears timer. */
  function _clearIdleVariation() {
    if (_idleLoopCleanup) { _idleLoopCleanup(); _idleLoopCleanup = null; }
    clearTimeout(_idleTimer);
  }

  /**
   * Schedule the next idle variation to fire after 3–12 full loops of the
   * main D1 video. Loop detection: currentTime drops by >0.5s = video wrapped.
   */
  function _scheduleIdleVariation() {
    _clearIdleVariation();
    if (_currentScene !== 'd1') return;

    const targetLoops = 3 + Math.floor(Math.random() * 10); // 3..12
    let loopCount = 0;
    let lastTime = -1;

    const vid = activeLoop();

    const onTimeUpdate = () => {
      const t = vid.currentTime;
      if (lastTime > 0.5 && t < lastTime - 0.5) {
        loopCount++;
        if (loopCount >= targetLoops) {
          _clearIdleVariation();
          _playIdleVariation();
          return;
        }
      }
      lastTime = t;
    };

    vid.addEventListener('timeupdate', onTimeUpdate);
    _idleLoopCleanup = () => vid.removeEventListener('timeupdate', onTimeUpdate);
  }

  function _playIdleVariation() {
    if (_currentScene !== 'd1' || _transitioning) return;

    const vars = LOOPS.d1.slice(1);
    const src = vars[Math.floor(Math.random() * vars.length)];

    // ── Phase 1: show PNG instantly while variation buffers ──────────────────
    staticBg.src = STATIC_PNG.d1;
    staticBg.style.transition = 'none';
    staticBg.style.opacity = '1';
    activeLoop().style.transition = 'none';
    activeLoop().style.opacity = '0';        // hide current main loop

    const idle = inactiveLoop();
    idle.src = src;
    idle.loop = false;
    idle.style.transition = 'none';
    idle.style.opacity = '0';               // keep hidden until canplay

    // ── GUARD: all callbacks check _currentScene before touching the DOM ─────
    // If the user navigates away while the variation is playing, these handlers
    // would otherwise corrupt the background of the new scene.

    idle.oncanplay = () => {
      if (_currentScene !== 'd1') { idle.oncanplay = null; return; }
      idle.oncanplay = null;
      // ── Phase 2: snap variation in, PNG off ─────────────────────────────
      idle.style.transition = 'none';
      idle.style.opacity = '1';
      staticBg.style.transition = 'none';
      staticBg.style.opacity = '0';
    };

    idle.onended = () => {
      idle.onended = null;
      idle.onerror = null;

      // Guard: if the user navigated away, do not restore D1 background
      if (_currentScene !== 'd1') return;

      // ── Phase 3: show PNG again while main loop re-buffers ────────────────
      staticBg.src = STATIC_PNG.d1;
      staticBg.style.transition = 'none';
      staticBg.style.opacity = '1';
      idle.style.transition = 'none';
      idle.style.opacity = '0';             // hide finished variation

      // inactiveLoop() is the same element as idle (_activeIsA not yet swapped).
      // Reuse this slot for the main loop — then swap _activeIsA so it becomes active.
      const main = inactiveLoop();
      main.src = LOOPS.d1[0];
      main.loop = true;
      main.style.transition = 'none';
      main.style.opacity = '0';

      main.oncanplay = () => {
        if (_currentScene !== 'd1') { main.oncanplay = null; return; }
        main.oncanplay = null;
        // ── Phase 4: snap main loop in, PNG off ─────────────────────────
        main.style.transition = 'none';
        main.style.opacity = '1';
        staticBg.style.transition = 'none';
        staticBg.style.opacity = '0';
        _activeIsA = !_activeIsA;           // swap: main is now the active slot
        _scheduleIdleVariation();
      };

      main.onerror = () => {
        if (_currentScene !== 'd1') { main.onerror = null; return; }
        main.oncanplay = null;
        _showStaticFallback('d1');
      };
      _safePlay(main);
    };

    idle.onerror = () => {
      idle.oncanplay = null;
      idle.onended = null;

      if (_currentScene !== 'd1') { idle.onerror = null; return; }

      // Recovery: snap the current main loop back in over the PNG
      const main = activeLoop();
      main.style.transition = 'none';
      main.style.opacity = '1';
      staticBg.style.transition = 'none';
      staticBg.style.opacity = '0';
      _scheduleIdleVariation();
    };

    _safePlay(idle);
  }

  // ── Public API ────────────────────────────────────────────────────────────

  function preload() {
    loopA      = document.getElementById('loop-video-a');
    loopB      = document.getElementById('loop-video-b');
    transVideo = document.getElementById('transition-video');
    staticBg   = document.getElementById('static-bg');

    // ── Preload static PNGs into browser cache ───────────────────────────────
    // Each PNG is the exact first frame of its scene's loop video.
    // Preloading ensures zero-delay when they're used as placeholders.
    Object.values(STATIC_PNG).forEach(src => {
      const img = new Image();
      img.src = src;
    });

    // ── Preload all video files ──────────────────────────────────────────────
    const allSrcs = [
      ...Object.values(LOOPS).flat(),
      ...Object.values(TRANSITIONS).filter(Boolean),
    ];

    allSrcs.forEach(src => {
      const v = document.createElement('video');
      v.src = src;
      v.preload = 'auto';
      v.style.display = 'none';
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
    _clearIdleVariation();

    const srcs = LOOPS[scene];
    if (!srcs || srcs.length === 0) {
      _showStaticFallback(scene);
      return;
    }

    // Pin the correct scene PNG instantly — exact match with the video's first
    // frame, so there is zero visual gap while the video buffers.
    staticBg.src = STATIC_PNG[scene] || STATIC_PNG.d1;
    staticBg.style.transition = 'none';
    staticBg.style.opacity = '1';

    const vid = activeLoop();
    vid.style.transition = 'none';
    vid.style.opacity = '0';
    // Ensure the inactive slot is also hidden (could be mid-fade from a variation)
    inactiveLoop().style.transition = 'none';
    inactiveLoop().style.opacity = '0';

    vid.src = srcs[0];
    vid.loop = true;

    vid.oncanplay = () => {
      vid.oncanplay = null;
      vid.style.transition = 'none';
      vid.style.opacity = '1';
      staticBg.style.transition = 'none';
      staticBg.style.opacity = '0';
    };
    vid.onerror = () => { vid.oncanplay = null; _showStaticFallback(scene); };
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
    _clearIdleVariation();

    // Hide both loop videos immediately so the old scene never bleeds through.
    loopA.style.transition = 'none';
    loopA.style.opacity = '0';
    loopB.style.transition = 'none';
    loopB.style.opacity = '0';

    // Show the source PNG immediately to fill the gap while the transition
    // video buffers. Without this, staticBg (turned off by playLoop's canplay)
    // stays invisible and the gap reads as a black flash.
    staticBg.src = STATIC_PNG[_currentScene] || STATIC_PNG.d1;
    staticBg.style.transition = 'none';
    staticBg.style.opacity = '1';

    const dest = key.split('→')[1];

    transVideo.src = src;
    transVideo.loop = false;

    const finish = () => {
      // Pin the destination PNG before the transition video disappears.
      // Because the PNG is pre-cached, this is instantaneous with no blank frame.
      staticBg.src = STATIC_PNG[dest] || STATIC_PNG.d1;
      staticBg.style.transition = 'none';
      staticBg.style.opacity = '1';

      // Snap the transition video off in the same paint frame — no fade-out,
      // so the last frame of the transition video never bleeds through.
      transVideo.style.transition = 'none';
      transVideo.style.opacity = '0';
      transVideo.onended = null;
      transVideo.onerror = null;
      transVideo.oncanplay = null;
      _transitioning = false;
      onComplete(); // → playLoop(dest) → video starts hidden, fades in over PNG
    };

    transVideo.onended = finish;
    transVideo.onerror = () => {
      _showStaticFallback(dest);
      finish();
    };

    // Keep the transition video hidden until its first frame is decoded.
    // Snap it in (no fade) to avoid any blend with a potentially dark start frame.
    transVideo.style.transition = 'none';
    transVideo.style.opacity = '0';
    transVideo.oncanplay = () => {
      transVideo.oncanplay = null;
      transVideo.style.opacity = '1'; // snap in — first frame is already decoded
    };
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
