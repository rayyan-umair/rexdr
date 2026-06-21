/**
 * rexdr - Frontend
 * components/TopBar/TopBar.jsx - Global top navigation bar
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Persistent top bar with global search trigger, live alert
 *           count, AI assistant toggle, and platform status. The
 *           command palette (Cmd+K) is triggered from here. This is
 *           the bar that stays visible across every engine view,
 *           giving the platform a consistent operating frame.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useState } from "react";
import { Search, Bell, Sparkles, Circle } from "lucide-react";
import { colors } from "../../design/tokens";

export default function TopBar({ onOpenSearch, onToggleAI, alertCount = 0, aiEnabled = false }) {
  const [now, setNow] = useState(new Date());

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

        <button
          style={{
            position: "relative",
            width: "34px",
            height: "34px",
            borderRadius: "8px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: colors.surface,
            border: `1px solid ${colors.border}`,
            color: colors.textSecondary,
          }}
        >
          <Bell size={15} />
          {alertCount > 0 && (
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
              {alertCount > 99 ? "99+" : alertCount}
            </span>
          )}
        </button>
      </div>
    </div>
  );
}