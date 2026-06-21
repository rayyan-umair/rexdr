/**
 * rexdr - Frontend
 * components/EntityRiskBoard/EntityRiskBoard.jsx - Risk-sorted entity list
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Shows every tracked entity sorted by composite risk score
 *           descending. This is the view that makes REXDR's unified
 *           entity model tangible - one IP or username with a single
 *           risk number reflecting everything every engine has
 *           observed about it, not eight separate per-tool scores.
 *           Pulls from the SIEM engine's chain data and cross-engine
 *           detection feeds since there is no standalone entity API
 *           endpoint - the board is assembled client-side from what
 *           is currently live across the platform.
 *
 * --- Part of the REXDR platform. ---
 */

import { useMemo, useState } from "react";
import { Users } from "lucide-react";
import { colors } from "../../design/tokens";
import { useAllEnginesStream } from "../../hooks/useLiveStream";
import EmptyState from "../Shared/EmptyState";
import Card from "../Shared/Card";

function riskColor(score) {
  if (score >= 75) return colors.critical;
  if (score >= 50) return colors.high;
  if (score >= 25) return colors.medium;
  return colors.low;
}

export default function EntityRiskBoard({ onSelectEntity }) {
  const messages = useAllEnginesStream(500);

  const entities = useMemo(() => {
    const map = new Map();

    messages
      .filter((m) => m.type === "detection" && m.data?.entity_id)
      .forEach((m) => {
        const id = m.data.entity_id;
        const existing = map.get(id) || {
          entityId: id,
          entityType: m.data.entity_type,
          engines: new Set(),
          detectionCount: 0,
          highestSeverity: "info",
          lastSeen: m.timestamp,
        };

        existing.engines.add(m.sourceEngine);
        existing.detectionCount += 1;
        existing.lastSeen = m.timestamp;

        const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        if ((rank[m.data.severity] || 0) > (rank[existing.highestSeverity] || 0)) {
          existing.highestSeverity = m.data.severity;
        }

        map.set(id, existing);
      });

    const rankWeight = { critical: 85, high: 50, medium: 25, low: 10, info: 2 };

    return Array.from(map.values())
      .map((e) => ({
        ...e,
        engineCount: e.engines.size,
        riskScore: Math.min(
          100,
          Math.round(
            (rankWeight[e.highestSeverity] || 0) * (1 + (e.engines.size - 1) * 0.35)
          )
        ),
      }))
      .sort((a, b) => b.riskScore - a.riskScore);
  }, [messages]);

  if (entities.length === 0) {
    return (
      <EmptyState
        icon={Users}
        title="No tracked entities yet"
        description="As engines observe IPs, usernames, and hosts, they will appear here ranked by composite risk score across every engine."
      />
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px", padding: "16px" }}>
      {entities.map((entity) => (
        <Card
          key={entity.entityId}
          hoverable
          onClick={() => onSelectEntity?.(entity)}
          style={{ display: "flex", alignItems: "center", gap: "16px" }}
        >
          <RiskRing score={entity.riskScore} />

          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: "13px",
                fontWeight: 700,
                color: colors.textPrimary,
                fontFamily: "'JetBrains Mono', monospace",
                marginBottom: "3px",
              }}
            >
              {entity.entityId}
            </div>
            <div style={{ fontSize: "12px", color: colors.textTertiary }}>
              {entity.detectionCount} detection{entity.detectionCount !== 1 ? "s" : ""} across{" "}
              {entity.engineCount} engine{entity.engineCount !== 1 ? "s" : ""}
            </div>
          </div>

          {entity.engineCount >= 2 && (
            <div
              style={{
                fontSize: "11px",
                fontWeight: 700,
                color: colors.accent,
                background: colors.accentSoft,
                border: `1px solid ${colors.accent}33`,
                borderRadius: "999px",
                padding: "3px 10px",
                whiteSpace: "nowrap",
              }}
            >
              CROSS-ENGINE
            </div>
          )}
        </Card>
      ))}
    </div>
  );
}

function RiskRing({ score }) {
  const color = riskColor(score);
  const circumference = 2 * Math.PI * 16;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div style={{ position: "relative", width: "44px", height: "44px", flexShrink: 0 }}>
      <svg width="44" height="44" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="22" cy="22" r="16" fill="none" stroke={colors.border} strokeWidth="3" />
        <circle
          cx="22"
          cy="22"
          r="16"
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "11px",
          fontWeight: 700,
          color,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        {score}
      </div>
    </div>
  );
}