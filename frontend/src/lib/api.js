/**
 * rexdr - Frontend
 * lib/api.js - Unified API client for all eight engines
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Single client for talking to every REXDR engine API. Routes
 *           through the Nginx gateway in production so the browser only
 *           ever talks to one origin. In local dev, Vite's proxy or
 *           direct engine ports can be used via VITE_API_BASE.
 *           No component calls fetch() directly - everything goes
 *           through this module so request shape stays consistent.
 *
 * --- Part of the REXDR platform. ---
 */

const BASE = import.meta.env.VITE_API_BASE || "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`REXDR API error ${res.status}: ${text || res.statusText}`);
  }

  return res.json();
}

// -- Windows Event Intelligence ----------------------------------------------
export const windowsEvent = {
  health:     () => request("/windows-event/health"),
  events:     (limit = 100) => request(`/windows-event/events?limit=${limit}`),
  detections: (limit = 50, severity) =>
    request(`/windows-event/detections?limit=${limit}${severity ? `&severity=${severity}` : ""}`),
  stats:      () => request("/windows-event/stats"),
};

// -- Network Flow Intelligence ------------------------------------------------
export const networkFlow = {
  health:     () => request("/network-flow/health"),
  flows:      (limit = 100) => request(`/network-flow/flows?limit=${limit}`),
  detections: (limit = 50, severity) =>
    request(`/network-flow/detections?limit=${limit}${severity ? `&severity=${severity}` : ""}`),
  stats:      () => request("/network-flow/stats"),
};

// -- SIEM Correlation ----------------------------------------------------------
export const siem = {
  health: () => request("/siem/health"),
  chains: (limit = 50, activeOnly = false) =>
    request(`/siem/chains?limit=${limit}&active_only=${activeOnly}`),
  chain:  (chainId) => request(`/siem/chains/${chainId}`),
  rules:  () => request("/siem/rules"),
  stats:  () => request("/siem/stats"),
  ask:    (context, question) =>
    request("/siem/ai/ask", {
      method: "POST",
      body: JSON.stringify({ context, question }),
    }),
  aiStatus: () => request("/siem/ai/status"),
};

// -- DNS Behavioral Intelligence -----------------------------------------------
export const dns = {
  health:     () => request("/dns/health"),
  queries:    (limit = 100) => request(`/dns/queries?limit=${limit}`),
  detections: (limit = 50, severity) =>
    request(`/dns/detections?limit=${limit}${severity ? `&severity=${severity}` : ""}`),
  stats:      () => request("/dns/stats"),
};

// -- Active Directory Intelligence ---------------------------------------------
export const identity = {
  health:     () => request("/identity/health"),
  detections: (limit = 50, severity) =>
    request(`/identity/detections?limit=${limit}${severity ? `&severity=${severity}` : ""}`),
  stats:      () => request("/identity/stats"),
};

// -- Incident Response Orchestration -------------------------------------------
export const response = {
  health:    () => request("/response/health"),
  cases:     (limit = 50) => request(`/response/cases?limit=${limit}`),
  case:      (caseId) => request(`/response/cases/${caseId}`),
  actions:   (limit = 100) => request(`/response/actions?limit=${limit}`),
  playbooks: () => request("/response/playbooks"),
  stats:     () => request("/response/stats"),
};

// -- Network Discovery ----------------------------------------------------------
export const assetDiscovery = {
  health:     () => request("/asset-discovery/health"),
  assets:     () => request("/asset-discovery/assets"),
  asset:      (ip) => request(`/asset-discovery/assets/${ip}`),
  detections: (limit = 50, severity) =>
    request(`/asset-discovery/detections?limit=${limit}${severity ? `&severity=${severity}` : ""}`),
  stats:      () => request("/asset-discovery/stats"),
};

// -- Vulnerability Intelligence ---------------------------------------------------
export const vulnerability = {
  health:           () => request("/vulnerability/health"),
  vulnerabilities:  (limit = 200) => request(`/vulnerability/vulnerabilities?limit=${limit}`),
  assetVulns:       (ip) => request(`/vulnerability/vulnerabilities/${ip}`),
  detections:       (limit = 50, severity) =>
    request(`/vulnerability/detections?limit=${limit}${severity ? `&severity=${severity}` : ""}`),
  stats:            () => request("/vulnerability/stats"),
};

// -- Engine registry for generic / aggregate calls -----------------------------
export const ENGINE_CLIENTS = {
  windows_event:    windowsEvent,
  network_flow:     networkFlow,
  siem:             siem,
  dns:              dns,
  identity:         identity,
  response:         response,
  asset_discovery:  assetDiscovery,
  vulnerability:    vulnerability,
};

export async function fetchAllEngineHealth() {
  const entries = Object.entries(ENGINE_CLIENTS);
  const results = await Promise.allSettled(
    entries.map(([, client]) => client.health())
  );

  return entries.reduce((acc, [engineId], i) => {
    const result = results[i];
    acc[engineId] = result.status === "fulfilled"
      ? result.value
      : { status: "unreachable", engine: engineId };
    return acc;
  }, {});
}

export async function fetchAllDetections(limit = 30) {
  const entries = Object.entries(ENGINE_CLIENTS).filter(
    ([id]) => id !== "response" // response has no /detections endpoint
  );

  const results = await Promise.allSettled(
    entries.map(([, client]) => client.detections(limit))
  );

  let combined = [];
  results.forEach((result) => {
    if (result.status === "fulfilled") {
      combined = combined.concat(result.value.detections || []);
    }
  });

  return combined.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}