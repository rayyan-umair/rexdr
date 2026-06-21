/**
 * rexdr - Frontend
 * hooks/useEngineHealth.js - Live engine health polling hook
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Polls the health endpoint of all eight engines on an
 *           interval and exposes the current status map. Used by the
 *           sidebar and the launcher-style status dashboard view to
 *           show which engines are healthy, degraded, or unreachable.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useState, useCallback } from "react";
import { fetchAllEngineHealth } from "../lib/api";

const POLL_INTERVAL_MS = 15000;

export function useEngineHealth() {
  const [health, setHealth] = useState({});
  const [loading, setLoading] = useState(true);

  const poll = useCallback(async () => {
    try {
      const result = await fetchAllEngineHealth();
      setHealth(result);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    poll();
    const interval = setInterval(poll, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [poll]);

  return { health, loading, refresh: poll };
}