/**
 * rexdr - Frontend
 * pages/EngineView.jsx - Per-engine detail page
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Single templated page that renders the detail view for
 *           whichever of the eight engines is active, based on the
 *           route param. Shows engine-specific stats, recent detections,
 *           and the live stream scoped to that engine only. One
 *           component serves all eight engines rather than duplicating
 *           near-identical pages eight times.
 *
 * --- Part of the REXDR platform. ---
 */

import { useState } from "react";
import { useParams } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { colors, ENGINES } from "../design/tokens";
import { usePolling } from "../hooks/usePolling";
import { useLiveStream } from "../hooks/useLiveStream";
import { ENGINE_CLIENTS } from "../lib/api";
import StatTile from "../components/Shared/StatTile";
import SeverityBadge from "../components/Shared/SeverityBadge";
import EmptyState from "../components/Shared/EmptyState";
import InvestigationBlade from "../components/InvestigationBlade/InvestigationBlade";
import { formatDistanceToNow } from "date-fns";

export default function EngineView({ onAskAI }) {
  const { engineId } = useParams();
  const engine = ENGINES[engineId];
  const client = ENGINE_CLIENTS[engineId];
  const [selected, setSelected] = useState(null);

  const { data: statsData } = usePolling(
    () => client.stats(),
    15000,
    [engineId]
  );

  const liveMessages = useLiveStream(engineId, 100);

  const { data: detectionsData } = usePolling(
    () => client.detections?.(30) || Promise.resolve({ detections: [] }),
    20000,
    [engineId]
  );

  if (!engine) {
    return <EmptyState icon={AlertTriangle} title="Unknown engine" />;
  }

  const stats = statsData?.stats || {};
  const detections = detectionsData?.detections || [];

  return (
    <div style={{ display: "flex", height: "100%" }}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflowY: "auto" }}>
        <div style={{ padding: "20px", borderBottom: `1px solid ${colors.border}` }}>
          <div style={{ fontSize: "18px", fontWeight: 700, color: colors.textPrimary, marginBottom: "4px" }}>
            {engine.label}
          </div>
          <div style={{ fontSize: "12px", color: colors.textTertiary, fontFamily: "'JetBrains Mono', monospace" }}>
            {engineId}
          </div>
        </div>

        <div style={{ display: "flex", gap: "12px", padding: "20px", flexWrap: "wrap" }}>
          {Object.entries(stats).map(([key, value]) => (
            <StatTile
              key={key}
              label={key.replace(/_/g, " ")}
              value={value}
              accentColor={
                key.includes("critical") && value > 0
                  ? colors.critical
                  : key.includes("open") && value > 0
                  ? colors.medium
                  : undefined
              }
            />
          ))}
        </div>

        <div style={{ padding: "0 20px 20px" }}>
          <div
            style={{
              fontSize: "12px",
              fontWeight: 700,
              color: colors.textTertiary,
              letterSpacing: "0.05em",
              marginBottom: "12px",
            }}
          >
            RECENT DETECTIONS
          </div>

          {detections.length === 0 ? (
            <EmptyState
              icon={AlertTriangle}
              title="No detections yet"
              description={`${engine.label} has not produced any detections in the current retention window.`}
            />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
              {detections.map((d) => (
                <div
                  key={d.detection_id}
                  onClick={() => setSelected({ type: "detection", data: d, sourceEngine: engineId })}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    padding: "12px 14px",
                    borderRadius: "8px",
                    cursor: "pointer",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <SeverityBadge severity={d.severity} size="sm" />
                  <span
                    style={{
                      fontSize: "11px",
                      color: colors.textTertiary,
                      fontFamily: "'JetBrains Mono', monospace",
                      flexShrink: 0,
                    }}
                  >
                    {d.detection_code}
                  </span>
                  <span
                    style={{
                      fontSize: "13px",
                      color: colors.textPrimary,
                      flex: 1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {d.title}
                  </span>
                  <span style={{ fontSize: "11px", color: colors.textTertiary, flexShrink: 0 }}>
                    {d.timestamp && formatDistanceToNow(new Date(d.timestamp), { addSuffix: true })}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {selected && (
        <InvestigationBlade
          item={selected}
          onClose={() => setSelected(null)}
          onAskAI={onAskAI}
        />
      )}
    </div>
  );
}