"""
ws_server.py — Background HTTP + WebSocket servers for the live visualizer.

Ports
-----
HTTP  : 8765  ← serves static/index.html + REST API (/api/run, /api/history, /api/evaluate)
WS    : 8766  ← WebSocket endpoint consumed by the HTML page

Usage (called from main.py / server.py)
----------------------------------------
    from threat_system.visualizer.ws_server import (
        start_server, broadcast,
        register_run_handler, run_started, run_complete, set_confidence,
    )

    start_server()
    register_run_handler(my_pipeline_fn)
    broadcast("event", {"narration": {...}, "raw": {...}})
"""
from __future__ import annotations

import asyncio
import http.server
import json
import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
HTTP_PORT  = 8765
WS_PORT    = 8766
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# ------------------------------------------------------------------
# Shared WebSocket client registry
# ------------------------------------------------------------------
_clients: set        = set()
_clients_lock        = threading.Lock()
_ws_loop: asyncio.AbstractEventLoop | None = None
_started             = False

# ------------------------------------------------------------------
# Persistent state
# ------------------------------------------------------------------
_state_lock              = threading.Lock()
_current_run_events: list[dict] = []   # events for current/last run (for replay on connect)
_run_history:        list[dict] = []   # last 10 completed run summaries
_run_handler                    = None # callable(payload: dict) registered by main.py
_current_confidence: float      = 0.0  # captured from InvestigatorResult for run_complete
_MAX_HISTORY                    = 10


# ------------------------------------------------------------------
# Public: register pipeline trigger
# ------------------------------------------------------------------

def register_run_handler(fn) -> None:
    """Register callable(payload: dict) invoked when browser POSTs /api/run."""
    global _run_handler
    _run_handler = fn


# ------------------------------------------------------------------
# Public: confidence capture (called from _make_stage_handler)
# ------------------------------------------------------------------

def set_confidence(value: float) -> None:
    """Store the InvestigatorResult confidence so run_complete can include it."""
    global _current_confidence
    _current_confidence = float(value)


# ------------------------------------------------------------------
# Public: run lifecycle hooks
# ------------------------------------------------------------------

def run_started(label: str) -> None:
    """Call before each event starts.  Clears _current_run_events for the new run."""
    global _current_run_events, _current_confidence
    with _state_lock:
        _current_run_events  = [{"stage": "__label__", "label": label}]
        _current_confidence  = 0.0
    broadcast("run_start", {"label": label})


def run_complete(summary: dict) -> None:
    """Call after each event finishes.  Saves trace to history, broadcasts summary."""
    with _state_lock:
        _run_history.append({
            "label":   summary.get("event_id", "?"),
            "summary": summary,
            "events":  list(_current_run_events),
        })
        del _run_history[:-_MAX_HISTORY]
    broadcast("run_complete", summary)


# ------------------------------------------------------------------
# Thread-safe broadcast
# ------------------------------------------------------------------

def broadcast(stage: str, payload: dict[str, Any]) -> None:
    """Send a JSON message to all WS clients; persist to current-run buffer."""
    message_dict = {"stage": stage, **payload}

    # Persist pipeline events (skip lifecycle meta-messages)
    if stage not in ("run_start", "run_complete", "__label__"):
        with _state_lock:
            _current_run_events.append(message_dict)

    if _ws_loop is None:
        return
    message = json.dumps(message_dict, default=str)
    asyncio.run_coroutine_threadsafe(_broadcast_all(message), _ws_loop)


async def _broadcast_all(message: str) -> None:
    with _clients_lock:
        targets = set(_clients)
    if not targets:
        return
    results = await asyncio.gather(
        *[_send_safe(c, message) for c in targets],
        return_exceptions=True,
    )
    for client, result in zip(list(targets), results):
        if isinstance(result, Exception):
            with _clients_lock:
                _clients.discard(client)


async def _send_safe(client: Any, message: str) -> None:
    await client.send(message)


# ------------------------------------------------------------------
# WebSocket handler — replay current state on connect
# ------------------------------------------------------------------

async def _ws_handler(websocket: Any) -> None:
    with _clients_lock:
        _clients.add(websocket)

    # Send current run state immediately so late-connecting browsers see it.
    with _state_lock:
        snapshot = list(_current_run_events)
    if snapshot:
        try:
            await websocket.send(json.dumps(
                {"stage": "__replay__", "events": snapshot}, default=str
            ))
        except Exception:
            pass

    try:
        async for raw in websocket:
            try:
                cmd = json.loads(raw)
            except Exception:
                continue
            if cmd.get("type") == "__request_replay__":
                await _send_history_replay(websocket, cmd.get("event_id"))
    finally:
        with _clients_lock:
            _clients.discard(websocket)


async def _send_history_replay(websocket: Any, event_id: str | None) -> None:
    """Find a past run by event_id and send its full trace to one client."""
    if not event_id:
        return
    with _state_lock:
        events = None
        for entry in reversed(_run_history):
            lid     = entry.get("label")
            sid     = entry.get("summary", {}).get("event_id")
            if lid == event_id or sid == event_id:
                events = list(entry.get("events", []))
                break
    if events is None:
        return
    try:
        await websocket.send(json.dumps(
            {"stage": "__replay__", "events": events}, default=str
        ))
    except Exception:
        pass


# ------------------------------------------------------------------
# WebSocket server thread
# ------------------------------------------------------------------

def _run_ws_thread() -> None:
    global _ws_loop
    try:
        import websockets                # type: ignore[import]
    except ImportError:
        print(
            f"\n  [visualizer] ERROR: websockets not installed. "
            f"Fix: py -m pip install websockets>=12.0\n",
            flush=True,
        )
        return

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _server_forever() -> None:
        async with websockets.serve(_ws_handler, "localhost", WS_PORT):
            print(f"  WebSocket   -> ws://localhost:{WS_PORT}", flush=True)
            _ws_loop.__setattr__("_vis_ready", True)   # mark ready
            await asyncio.Future()

    try:
        # Mark the loop before run so broadcast() can use it immediately.
        _ws_loop = loop
        loop.run_until_complete(_server_forever())
    except OSError as exc:
        print(
            f"\n  [visualizer] WebSocket FAILED to bind port {WS_PORT}: {exc}\n"
            f"  -> Is another process already using port {WS_PORT}? "
            f"Try: netstat -ano | findstr :{WS_PORT}\n",
            flush=True,
        )
        _ws_loop = None
    except Exception as exc:
        print(
            f"\n  [visualizer] WebSocket server error: {type(exc).__name__}: {exc}\n",
            flush=True,
        )
        _ws_loop = None


# ------------------------------------------------------------------
# HTTP handler — static files + REST API
# ------------------------------------------------------------------

class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Serves STATIC_DIR for GET /; REST API on /api/*."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:   # type: ignore[override]
        pass

    def log_error(self, fmt: str, *args: Any) -> None:     # type: ignore[override]
        pass

    def end_headers(self) -> None:                         # type: ignore[override]
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self) -> None:                               # type: ignore[override]
        if self.path == "/api/history":
            self._json_response(_history_payload())
        else:
            super().do_GET()

    def do_POST(self) -> None:                              # type: ignore[override]
        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if self.path == "/api/run":
            self._trigger_run(payload)
        elif self.path == "/api/evaluate":
            self._trigger_run({"evaluate": True})
        else:
            self.send_response(404)
            self.end_headers()

    def _json_response(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _trigger_run(self, payload: dict) -> None:
        if _run_handler is None:
            self._json_response({"ok": False, "error": "No run handler registered"}, 503)
            return
        threading.Thread(target=_run_handler, args=(payload,), daemon=True).start()
        self._json_response({"ok": True})


def _history_payload() -> list[dict]:
    """Return last 10 run summaries for the sidebar (no full event traces)."""
    with _state_lock:
        entries = list(_run_history[-_MAX_HISTORY:])
    result = []
    for e in reversed(entries):
        summary = e.get("summary", {})
        result.append({
            "event_id":       summary.get("event_id") or e.get("label", "?"),
            "target":         summary.get("target", "?"),
            "final_action":   summary.get("final_action", "?"),
            "classification": summary.get("classification", "?"),
            "confidence":     summary.get("confidence", 0.0),
        })
    return result


# ------------------------------------------------------------------
# HTTP server thread
# ------------------------------------------------------------------

def _run_http_thread() -> None:
    try:
        server = http.server.ThreadingHTTPServer(("localhost", HTTP_PORT), _QuietHandler)
    except OSError as exc:
        print(
            f"\n  [visualizer] HTTP FAILED to bind port {HTTP_PORT}: {exc}\n"
            f"  -> Kill any process on port {HTTP_PORT} and restart.\n"
            f"  -> Windows: netstat -ano | findstr :{HTTP_PORT}  then taskkill /PID <pid> /F\n",
            flush=True,
        )
        return
    server.serve_forever()


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------

def start_server() -> None:
    """Launch HTTP and WS servers as daemon threads. Idempotent."""
    global _started
    if _started:
        return
    _started = True

    # Configure file logging if no handlers are set (keeps terminal clean)
    if not logging.root.handlers:
        log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "visualizer.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        logging.basicConfig(
            filename=log_path,
            level=logging.WARNING,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )

    threading.Thread(target=_run_http_thread, daemon=True, name="vis-http").start()
    threading.Thread(target=_run_ws_thread,   daemon=True, name="vis-ws").start()

    print(f"\n  Visualizer -> http://localhost:{HTTP_PORT}\n")
