/**
 * rexdr - Frontend
 * hooks/useLiveStream.js - Live WebSocket data hook
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Subscribes a component to one engine's live WebSocket
 *           stream and accumulates incoming messages into a capped
 *           rolling array. Used by the alert stream, entity board,
 *           and campaign timeline views for real-time updates without
 *           each component managing its own socket lifecycle.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useRef, useState } from "react";
import { subscribeToEngine, subscribeToAllEngines } from "../lib/websocket";

const DEFAULT_MAX_ITEMS = 200;

/**
 * Subscribe to a single engine's live stream.
 * Returns the rolling list of messages, most recent first.
 */
export function useLiveStream(engineId, maxItems = DEFAULT_MAX_ITEMS) {
  const [messages, setMessages] = useState([]);
  const maxRef = useRef(maxItems);

  useEffect(() => {
    const unsubscribe = subscribeToEngine(engineId, (msg) => {
      setMessages((prev) => [msg, ...prev].slice(0, maxRef.current));
    });
    return unsubscribe;
  }, [engineId]);

  return messages;
}

/**
 * Subscribe to every engine's live stream simultaneously.
 * Used by the global alert stream which needs cross-engine visibility.
 * Each message is tagged with its source engineId.
 */
export function useAllEnginesStream(maxItems = DEFAULT_MAX_ITEMS) {
  const [messages, setMessages] = useState([]);
  const maxRef = useRef(maxItems);

  useEffect(() => {
    const unsubscribe = subscribeToAllEngines((engineId, msg) => {
      setMessages((prev) =>
        [{ ...msg, sourceEngine: engineId }, ...prev].slice(0, maxRef.current)
      );
    });
    return unsubscribe;
  }, []);

  return messages;
}