/**
 * state.js — D1 / D2 / D3 scene state machine.
 *
 * Scenes: d1 (main menu) → d2 (case cabinet) → d3 (run detail)
 * Investigation state is a no-op this phase (videos deferred).
 */

const State = (() => {

  const SCENE_ORDER = ['d1', 'd2', 'd3'];
  let _current = null;

  // ── Transition key lookup ────────────────────────────────────────────────
  function _transitionKey(from, to) {
    return `${from}→${to}`;
  }

  // ── UI side-effects per scene ────────────────────────────────────────────
  function applySceneUI(scene) {
    const cabinet  = document.getElementById('cabinet-panel');
    const tab      = document.getElementById('panel-tab');
    const mono     = document.getElementById('monologue-panel');
    const showPanel = (scene === 'd2' || scene === 'd3');

    // Cabinet panel: open in D2/D3, closed in D1/investigation
    cabinet.classList.toggle('visible', showPanel);

    // Tab: shown in D2/D3; tracks panel state
    if (tab) {
      tab.style.display = showPanel ? 'flex' : 'none';
      tab.classList.toggle('panel-open', showPanel);
    }

    // When entering D2 from outside, always reset panel to list view
    if (scene === 'd2') {
      Cabinet.reload();
      Cabinet.showList();
    }

    // Monologue: investigation only (deferred)
    mono.style.display = (scene === 'investigation') ? 'block' : 'none';

    // Agents reset when leaving investigation
    if (scene !== 'investigation') {
      Agents.reset();
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Jump directly to a scene (no transition video).
   * Used for initial page load.
   */
  function set(scene) {
    _current = scene;
    VideoManager.playLoop(scene);
    Hover.updateForScene(scene);
    applySceneUI(scene);
  }

  /**
   * Navigate forward or backward one scene with a transition video.
   * Blocked if a transition is already playing.
   */
  function go(direction) {
    if (VideoManager.isTransitioning()) return;

    const idx = SCENE_ORDER.indexOf(_current);
    if (idx === -1) return; // investigation or unknown — ignore

    let nextIdx;
    if (direction === 'forward') {
      nextIdx = idx + 1;
    } else if (direction === 'back') {
      nextIdx = idx - 1;
    } else {
      console.warn('[State] Unknown direction:', direction);
      return;
    }

    if (nextIdx < 0 || nextIdx >= SCENE_ORDER.length) return; // already at boundary

    const nextScene = SCENE_ORDER[nextIdx];
    const key = _transitionKey(_current, nextScene);

    VideoManager.playTransition(key, () => set(nextScene));
  }

  /**
   * Open a specific case: play D2→D3 transition (if in D2),
   * then show the case detail in the cabinet panel.
   * Safe to call from D3 as well (no transition, just swaps detail).
   */
  function openCase(caseData) {
    if (VideoManager.isTransitioning()) return;

    if (_current === 'd2') {
      const key = _transitionKey('d2', 'd3');
      VideoManager.playTransition(key, () => {
        _current = 'd3';
        VideoManager.playLoop('d3');
        Hover.updateForScene('d3');
        // Cabinet stays visible; switch to detail view
        Cabinet.showDetail(caseData);
      });
    } else if (_current === 'd3') {
      // Already in D3 — just swap the detail content
      Cabinet.showDetail(caseData);
    }
  }

  /**
   * Trigger investigation mode.
   * No-op this phase — investigation videos not yet available.
   */
  function startInvestigation() {
    console.warn('[State] startInvestigation() — investigation state deferred this phase');
  }

  /** Returns the current scene string. */
  function current() {
    return _current;
  }

  return { set, go, current, openCase, startInvestigation };

})();
