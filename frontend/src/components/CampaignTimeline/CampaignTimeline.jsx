/**
 * rexdr - Frontend
 * components/CampaignTimeline/CampaignTimeline.jsx - Attack chain timeline view
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Renders the chronological sequence of detections that make
 *           up a single cross-engine attack chain. This is the visual
 *           proof of REXDR's core differentiator - showing the exact
 *           moment isolated low-severity events from different engines
 *           became a single correlated campaign.
 *
 * --- Part of the REXDR platform. ---
 */

import { GitMerge, ArrowDown } from "lucide-react";
import { format } from "date-fns";
import { colors } from "../../design/tokens";
import SeverityBadge from "../Shared/SeverityBadge";
import EngineBadge from "../Shared/EngineBadge";
import EmptyState from "../Shared/EmptyState";

export default function CampaignTimeline({ chain }) {
  if (!chain) {
    return (
      <EmptyState
        icon={GitMerge}
        title="No chain selected"
        description="Select an attack chain from the alert stream to see its full cross-engine timeline."
      />
    );
  }

  const detections = chain.detections || [];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ padding: "16px 20px", borderBottom: `1px solid ${colors.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
          <SeverityBadge severity={chain.severity} />
          <span
            style={{
              fontSize: "11px",
              fontWeight: 700,
              color: colors.accent,
              letterSpacing: "0.06em",
            }}
          >
            CROSS-ENGINE ATTACK CHAIN
          </span>
        </div>
        <div style={{ fontSize: "16px", fontWeight: 700, color: colors.textPrimary, marginBottom: "4px" }}>
          {chain.title}
        </div>
        <div style={{ fontSize: "12px", color: colors.textTertiary, fontFamily: "'JetBrains Mono', monospace" }}>
          Entity: {chain.entity_id}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "24px 20px" }}>
        {detections.length === 0 ? (
          <div style={{ color: colors.textTertiary, fontSize: "13px" }}>
            No detection sequence available for this chain.
          </div>
        ) : (
          detections.map((d, i) => (
            <div key={d.detection_id || i}>
              <div style={{ display: "flex", gap: "16px", alignItems: "flex-start" }}>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    flexShrink: 0,
                    width: "24px",
                  }}
                >
                  <div
                    style={{
                      width: "24px",
                      height: "24px",
                      borderRadius: "999px",
                      background: colors.surfaceRaised,
                      border: `2px solid ${colors.accent}`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: "11px",
                      fontWeight: 700,
                      color: colors.accent,
                      flexShrink: 0,
                    }}
                  >
                    {i + 1}
                  </div>
                </div>

                <div style={{ flex: 1, paddingBottom: "20px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                    <EngineBadge engineId={d.engine_id} />
                    <SeverityBadge severity={d.severity} size="sm" />
                    <span
                      style={{
                        fontSize: "11px",
                        color: colors.textTertiary,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {d.detection_code}
                    </span>
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 600, color: colors.textPrimary, marginBottom: "4px" }}>
                    {d.title}
                  </div>
                  <div style={{ fontSize: "12px", color: colors.textSecondary, lineHeight: 1.5 }}>
                    {d.description}
                  </div>
                  <div style={{ fontSize: "11px", color: colors.textTertiary, marginTop: "6px" }}>
                    {d.timestamp && format(new Date(d.timestamp), "MMM d, yyyy 'at' HH:mm:ss")}
                  </div>
                </div>
              </div>

              {i < detections.length - 1 && (
                <div style={{ display: "flex", justifyContent: "flex-start", marginLeft: "11px", marginTop: "-12px", marginBottom: "-8px" }}>
                  <ArrowDown size={14} color={colors.textTertiary} />
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {chain.narrative && (
        <div
          style={{
            padding: "16px 20px",
            borderTop: `1px solid ${colors.border}`,
            background: colors.surface,
          }}
        >
          <div
            style={{
              fontSize: "11px",
              fontWeight: 700,
              color: colors.textTertiary,
              letterSpacing: "0.05em",
              marginBottom: "8px",
            }}
          >
            INVESTIGATION NARRATIVE
          </div>
          <div
            style={{
              fontSize: "12px",
              color: colors.textSecondary,
              lineHeight: 1.6,
              whiteSpace: "pre-wrap",
              maxHeight: "160px",
              overflowY: "auto",
            }}
          >
            {chain.narrative}
          </div>
        </div>
      )}
    </div>
  );
}