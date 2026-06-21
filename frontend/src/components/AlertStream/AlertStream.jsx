/**
 * rexdr - Frontend
 * components/AlertStream/AlertStream.jsx - Live cross-engine alert feed
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Virtualised-feeling live stream of detections and attack
 *           chains across all eight engines, merged into a single
 *           chronological feed. This is the primary "what is happening
 *           right now" view - clicking any row opens the investigation
 *           blade for full context.
 *
 * --- Part of the REXDR platform. ---
 */

import { useMemo, useState } from "react";
import { AlertTriangle, GitMerge } from "lucide-react";
import { colors } from "../../design/tokens";
import { useAllEnginesStream } from "../../hooks/useLiveStream";
import SeverityBadge from "../Shared/SeverityBadge";
import EngineBadge from "../Shared/EngineBadge";
import EmptyState from "../Shared/EmptyState";
import { formatDistanceToNow } from "date-fns";

export default function AlertStream({ onSelect }) {
  const messages = useAllEnginesStream(300);
  const [filter, setFilter] = useState("all");

  const filtered = useMemo(() => {
    const relevant = messages.filter((m) =>
      ["detection", "attack_chain", "sigma_match", "case_file"].includes(m.type)
    );

    if (filter === "all") return relevant;
    if (filter === "chains") return relevant.filter((m) => m.type === "attack_chain");
    return relevant.filter((m) => m.type === "detection" && m.data?.severity === filter);
  }, [messages, filter]);

  const filters = [
    { id: "all", label: "All" },
    { id: "chains", label: "Chains" },
    { id: "critical", label: "Critical" },
    { id: "high", label: "High" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div
        style={{
          display: "flex",
          gap: "6px",
          padding: "12px 16px",
          borderBottom: `1px solid ${colors.border}`,
        }}
      >
        {filters.map((f) => (
          <button
            key={f.id}
            onClick={() => setFilter(f.id)}
            style={{
              padding: "5px 12px",
              borderRadius: "999px",
              fontSize: "12px",
              fontWeight: 600,
              background: filter === f.id ? colors.surfaceRaised : "transparent",
              color: filter === f.id ? colors.textPrimary : colors.textTertiary,
              border: `1px solid ${filter === f.id ? colors.borderStrong : "transparent"}`,
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        {filtered.length === 0 ? (
          <EmptyState
            icon={AlertTriangle}
            title="No live activity yet"
            description="Detections and attack chains will appear here in real time as engines process telemetry."
          />
        ) : (
          filtered.map((msg, i) => (
            <AlertRow key={`${msg.timestamp}-${i}`} message={msg} onSelect={onSelect} />
          ))
        )}
      </div>
    </div>
  );
}

function AlertRow({ message, onSelect }) {
  const isChain = message.type === "attack_chain";
  const data = message.data || {};
  const severity = data.severity;
  const title = data.title || data.rule_title || "Untitled event";
  const entityId = data.entity_id;

  return (
    <div
      onClick={() => onSelect?.(message)}
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "12px",
        padding: "12px 16px",
        borderBottom: `1px solid ${colors.border}`,
        cursor: "pointer",
        animation: "fade-in 0.2s ease",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      <div
        style={{
          width: "30px",
          height: "30px",
          borderRadius: "8px",
          background: isChain ? colors.accentSoft : colors.surfaceRaised,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        {isChain ? (
          <GitMerge size={14} color={colors.accent} />
        ) : (
          <AlertTriangle size={14} color={colors.textTertiary} />
        )}
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
          {isChain && (
            <span
              style={{
                fontSize: "10px",
                fontWeight: 700,
                color: colors.accent,
                letterSpacing: "0.05em",
              }}
            >
              ATTACK CHAIN
            </span>
          )}
          <SeverityBadge severity={severity} size="sm" />
          <EngineBadge engineId={message.sourceEngine} size="sm" />
        </div>
        <div
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: colors.textPrimary,
            marginBottom: "2px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {title}
        </div>
        {entityId && (
          <div style={{ fontSize: "12px", color: colors.textTertiary }}>
            Entity: <span style={{ color: colors.textSecondary }}>{entityId}</span>
          </div>
        )}
      </div>

      <div style={{ fontSize: "11px", color: colors.textTertiary, whiteSpace: "nowrap", flexShrink: 0 }}>
        {message.timestamp &&
          formatDistanceToNow(new Date(message.timestamp), { addSuffix: true })}
      </div>
    </div>
  );
}