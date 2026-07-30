/**
 * rexdr - Frontend
 * components/TopBar/TopBar.jsx - Global top navigation bar
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Updated : 2026-07-29 - The notification bell had a badge but no
 *           onClick, no hover state, and no dropdown anywhere in the
 *           codebase - a flagged-but-never-finished feature. Wired it
 *           up: clicking now fetches open, critical detections across
 *           every engine that exposes one (mirrors the exclusion logic
 *           already used elsewhere for siem/response, which don't),
 *           shows the most recent ones, and clicking a row navigates
 *           to that engine's page. Closes on click-outside.
 * Purpose : Persistent top bar with global search trigger, live alert
 *           count, AI assistant toggle, and platform status. The
 *           command palette (Cmd+K) is triggered from here. This is
 *           the bar that stays visible across every engine view,
 *           giving the platform a consistent operating frame.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search, Bell, Sparkles, Circle, AlertTriangle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { colors } from "../../design/tokens";
import { ENGINE_CLIENTS } from "../../lib/api";
import SeverityBadge from "../Shared/SeverityBadge";
import EngineBadge from "../Shared/EngineBadge";
import EmptyState from "../Shared/EmptyState";

const NOTIFICATION_DISPLAY_LIMIT = 50;
const SEEN_STORAGE_KEY = "rexdr.alerts.lastSeenCount";

export default function TopBar({ onOpenSearch, onToggleAI, alertCount = 0, aiEnabled = false }) {
  const [now, setNow] = useState(new Date());
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifLoading, setNotifLoading] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [notifTotal, setNotifTotal] = useState(0);
  const [bellHovered, setBellHovered] = useState(false);
  const [lastSeenCount, setLastSeenCount] = useState(() => {
    try {
      return Number(window.localStorage.getItem(SEEN_STORAGE_KEY)) || 0;
    } catch {
      return 0;
    }
  });
  const bellRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const interval = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenSearch?.();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onOpenSearch]);

  useEffect(() => {
    function handleClickOutside(e) {
      if (bellRef.current && !bellRef.current.contains(e.target)) {
        setNotifOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    if (!notifOpen) return;

    let cancelled = false;
    setNotifLoading(true);

    const clients = Object.values(ENGINE_CLIENTS).filter(
      (client) => typeof client?.detections === "function"
    );

    Promise.allSettled(clients.map((client) => client.detections(50)))
      .then((results) => {
        if (cancelled) return;

        const combined = [];
        for (const result of results) {
          if (result.status !== "fulfilled") continue;
          const detections = result.value?.detections || [];
          for (const d of detections) {
            if (d.status === "open" && d.severity === "critical") {
              combined.push(d);
            }
          }
        }

        combined.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        setNotifTotal(combined.length);
        setNotifications(combined.slice(0, NOTIFICATION_DISPLAY_LIMIT));
      })
      .finally(() => {
        if (!cancelled) setNotifLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [notifOpen]);

  // If alerts were closed elsewhere the total can drop below what was last
  // seen, which would leave the badge permanently suppressed. Clamp down so a
  // genuinely new alert still surfaces.
  useEffect(() => {
    if (alertCount < lastSeenCount) {
      persistSeenCount(alertCount);
    }
  }, [alertCount, lastSeenCount]);

  function persistSeenCount(count) {
    setLastSeenCount(count);
    try {
      window.localStorage.setItem(SEEN_STORAGE_KEY, String(count));
    } catch {
      // Storage unavailable (private mode, quota) - badge still clears for
      // this session, it just will not survive a reload.
    }
  }

  function toggleNotifications() {
    const opening = !notifOpen;
    setNotifOpen(opening);
    if (opening) {
      persistSeenCount(alertCount);
    }
  }

  function handleSelectNotification(d) {
    setNotifOpen(false);
    navigate(`/engine/${d.engine_id}`);
  }

  const unreadCount = Math.max(0, alertCount - lastSeenCount);

  return (
    <div
      style={{
        height: "56px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 20px",
        borderBottom: `1px solid ${colors.border}`,
        background: colors.background,
        flexShrink: 0,
      }}
    >
      <button
        onClick={onOpenSearch}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "8px 14px",
          borderRadius: "8px",
          background: colors.surface,
          border: `1px solid ${colors.border}`,
          color: colors.textTertiary,
          fontSize: "13px",
          width: "320px",
        }}
      >
        <Search size={15} />
        <span style={{ flex: 1, textAlign: "left" }}>Search entities, detections, chains...</span>
        <span
          style={{
            fontSize: "11px",
            color: colors.textTertiary,
            border: `1px solid ${colors.border}`,
            borderRadius: "4px",
            padding: "1px 6px",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          ⌘K
        </span>
      </button>

      <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontSize: "12px",
            color: colors.textTertiary,
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          <Circle size={7} fill={colors.success} color={colors.success} />
          {now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
        </div>

        <button
          onClick={onToggleAI}
          title="AI Investigation Assistant"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "7px 12px",
            borderRadius: "8px",
            background: aiEnabled ? colors.accentSoft : colors.surface,
            border: `1px solid ${aiEnabled ? colors.accent + "55" : colors.border}`,
            color: aiEnabled ? colors.accent : colors.textSecondary,
            fontSize: "12px",
            fontWeight: 600,
          }}
        >
          <Sparkles size={14} />
          AI
        </button>

        <div ref={bellRef} style={{ position: "relative" }}>
          <button
            onClick={() => setNotifOpen((v) => !v)}
            onMouseEnter={() => setBellHovered(true)}
            onMouseLeave={() => setBellHovered(false)}
            title="Critical alerts"
            style={{
              position: "relative",
              width: "34px",
              height: "34px",
              borderRadius: "8px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: notifOpen || bellHovered ? colors.surfaceRaised : colors.surface,
              border: `1px solid ${notifOpen ? colors.accent + "55" : colors.border}`,
              color: notifOpen ? colors.accent : colors.textSecondary,
            }}
          >
            <Bell size={15} />
            {unreadCount > 0 && (
              <span
                style={{
                  position: "absolute",
                  top: "-4px",
                  right: "-4px",
                  background: colors.critical,
                  color: "#fff",
                  fontSize: "10px",
                  fontWeight: 700,
                  borderRadius: "999px",
                  minWidth: "16px",
                  height: "16px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  padding: "0 4px",
                }}
              >
                {unreadCount > 99 ? "99+" : unreadCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div
              style={{
                position: "absolute",
                top: "calc(100% + 8px)",
                right: 0,
                width: "380px",
                maxHeight: "480px",
                display: "flex",
                flexDirection: "column",
                background: colors.surface,
                border: `1px solid ${colors.border}`,
                borderRadius: "12px",
                boxShadow: "0 12px 32px rgba(0, 0, 0, 0.35)",
                overflow: "hidden",
                zIndex: 50,
              }}
            >
              <div
                style={{
                  padding: "14px 16px",
                  borderBottom: `1px solid ${colors.border}`,
                  fontSize: "12px",
                  fontWeight: 700,
                  color: colors.textTertiary,
                  letterSpacing: "0.05em",
                }}
              >
                CRITICAL ALERTS {notifTotal > 0 && `(${notifTotal})`}
              </div>

              <div style={{ overflowY: "auto" }}>
                {notifLoading ? (
                  <div style={{ padding: "24px", fontSize: "13px", color: colors.textTertiary, textAlign: "center" }}>
                    Loading...
                  </div>
                ) : notifications.length === 0 ? (
                  <EmptyState
                    icon={AlertTriangle}
                    title="No critical alerts"
                    description="Open critical detections across every engine will show up here."
                  />
                ) : (
                  notifications.map((d) => (
                    <div
                      key={d.detection_id}
                      onClick={() => handleSelectNotification(d)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "10px",
                        padding: "12px 16px",
                        cursor: "pointer",
                        borderBottom: `1px solid ${colors.border}`,
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = colors.surfaceRaised)}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <SeverityBadge severity={d.severity} size="sm" />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            fontSize: "13px",
                            color: colors.textPrimary,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {d.title}
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px" }}>
                          <EngineBadge engineId={d.engine_id} />
                          <span style={{ fontSize: "11px", color: colors.textTertiary }}>
                            {d.timestamp && formatDistanceToNow(new Date(d.timestamp), { addSuffix: true })}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {notifTotal > notifications.length && (
                <div
                  style={{
                    padding: "10px 16px",
                    fontSize: "12px",
                    color: colors.textTertiary,
                    textAlign: "center",
                    borderTop: `1px solid ${colors.border}`,
                  }}
                >
                  +{notifTotal - notifications.length} more not shown
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}