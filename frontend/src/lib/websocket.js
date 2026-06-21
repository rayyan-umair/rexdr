/**
 * rexdr - Frontend
 * lib/websocket.js - Unified WebSocket connection manager
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Manages WebSocket connections to every engine's live stream
 *           endpoint. Handles reconnection with backoff, and exposes a
 *           simple subscribe/unsubscribe interface so React hooks stay
 *           thin. Routes through the Nginx gateway in production.
 *
 * --- Part of the REXDR platform. ---
 */

const WS_BASE = import.meta.env.VITE_WS_BASE || (
  window.location.protocol === "https:"
    ? `wss://${window.location.host}/ws-api`
    : `ws://${window.location.host}/ws-api`
);

const WS_PATHS = {
  windows_event:    "/windows-event/ws/events",
  network_flow:     "/network-flow/ws/flows",
  siem:             "/siem/ws/chains",
  dns:              "/dns/ws/queries",
  identity:         "/identity/ws/events",
  response:         "/response/ws/cases",
  asset_discovery:  "/asset-discovery/ws/assets",
  vulnerability:    "/vulnerability/ws/vulnerabilities",
};

const RECONNECT_BASE_DELAY_MS = 1000;
const RECONNECT_MAX_DELAY_MS = 30000;

class EngineSocket {
  constructor(engineId) {
    this.engineId = engineId;
    this.path = WS_PATHS[engineId];
    this.socket = null;
    this.listeners = new Set();
    this.reconnectAttempts = 0;
    this.shouldReconnect = true;
    this.connect();
  }

  connect() {
    if (!this.path) return;

    try {
      this.socket = new WebSocket(`${WS_BASE}${this.path}`);
    } catch (e) {
      this._scheduleReconnect();
      return;
    }

    this.socket.onopen = () => {
      this.reconnectAttempts = 0;
    };

    this.socket.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        if (parsed.type === "ping") return;
        this.listeners.forEach((cb) => cb(parsed));
      } catch {
        // Ignore malformed frames rather than crashing the stream
      }
    };

    this.socket.onclose = () => {
      if (this.shouldReconnect) this._scheduleReconnect();
    };

    this.socket.onerror = () => {
      this.socket?.close();
    };
  }

  _scheduleReconnect() {
    const delay = Math.min(
      RECONNECT_BASE_DELAY_MS * 2 ** this.reconnectAttempts,
      RECONNECT_MAX_DELAY_MS
    );
    this.reconnectAttempts += 1;
    setTimeout(() => {
      if (this.shouldReconnect) this.connect();
    }, delay);
  }

  subscribe(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  close() {
    this.shouldReconnect = false;
    this.socket?.close();
  }
}

const activeSockets = new Map();

/**
 * Get or create the shared socket instance for an engine.
 * Multiple components subscribing to the same engine share one
 * underlying connection rather than opening duplicate sockets.
 */
export function getEngineSocket(engineId) {
  if (!activeSockets.has(engineId)) {
    activeSockets.set(engineId, new EngineSocket(engineId));
  }
  return activeSockets.get(engineId);
}

export function subscribeToEngine(engineId, callback) {
  const socket = getEngineSocket(engineId);
  return socket.subscribe(callback);
}

export function subscribeToAllEngines(callback) {
  const unsubscribers = Object.keys(WS_PATHS).map((engineId) =>
    subscribeToEngine(engineId, (msg) => callback(engineId, msg))
  );
  return () => unsubscribers.forEach((unsub) => unsub());
}