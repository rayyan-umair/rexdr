/**
 * rexdr - Frontend
 * hooks/usePolling.js - Generic interval-based data fetching hook
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Generic hook for polling any async fetch function on an
 *           interval, with loading and error state. Used wherever a
 *           view needs REST data refreshed periodically rather than
 *           pushed via WebSocket - asset inventory, vulnerability
 *           lists, case files, and similar lower-frequency data.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useState, useCallback, useRef } from "react";

export function usePolling(fetchFn, intervalMs = 20000, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const fetchRef = useRef(fetchFn);
  fetchRef.current = fetchFn;

  const run = useCallback(async () => {
    try {
      const result = await fetchRef.current();
      setData(result);
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    run();
    const interval = setInterval(run, intervalMs);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, run, ...deps]);

  return { data, loading, error, refresh: run };
}