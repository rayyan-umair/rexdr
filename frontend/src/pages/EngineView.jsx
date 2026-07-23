/**
 * rexdr - Frontend
 * pages/EngineView.jsx - Per-engine detail page
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Updated : 2026-07-23 - Added a dedicated Assets table for the Asset
 *           Discovery engine, showing real inventory data (IP, hostname,
 *           MAC, OS fingerprint, open ports, services, last seen, scan
 *           count) instead of only ever showing detections. Previously
 *           this page only ever rendered "Recent Detections" for every
 *           engine, even though asset-discovery's /assets endpoint
 *           already returns rich per-host inventory data with nowhere
 *           in the UI to see it.
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
import { AlertTriangle, Server } from "lucide-react";
import { colors, ENGINES } from "../design/tokens";
import { usePolling } from "../hooks/usePolling";
import { useLiveStream } from "../hooks/useLiveStream";
import { ENGINE_CLIENTS } from "../lib/api";
import StatTile from "../components/Shared/StatTile";
import SeverityBadge from "../components/Shared/SeverityBadge";
import EmptyState from "../components/Shared/EmptyState";
import InvestigationBlade from "../components/InvestigationBlade/InvestigationBlade";
import { formatDistanceToNow } from "date-fns";

function safeParse(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

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

  const isAssetDiscovery = engineId === "asset_discovery";

  const { data: assetsData } = usePolling(
    () => (isAssetDiscovery ? client.assets() : Promise.resolve({ assets: [] })),
    20000,
    [engineId]
  );

  if (!engine) {
    return <EmptyState icon={AlertTriangle} title="Unknown engine" />;
  }

  const stats = statsData?.stats || {};
  const detections = detectionsData?.detections || [];
  const assets = assetsData?.assets || [];

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

        {isAssetDiscovery && (
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
              DISCOVERED ASSETS
            </div>

            {assets.length === 0 ? (
              <EmptyState
                icon={Server}
                title="No assets discovered yet"
                description="Discovered hosts will appear here once a scan cycle completes."
              />
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${colors.border}` }}>
                      {["IP Address", "Hostname", "MAC Address", "OS Fingerprint", "Open Ports", "Services", "Last Seen", "Scans"].map((h) => (
                        <th
                          key={h}
                          style={{
                            textAlign: "left",
                            padding: "8px 12px",
                            fontSize: "11px",
                            fontWeight: 700,
                            color: colors.textTertiary,
                            letterSpacing: "0.03em",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {assets.map((a) => {
                      const ports = safeParse(a.open_ports, []);
                      const services = safeParse(a.services, {});
                      return (
                        <tr
                          key={a.ip_address}
                          style={{ borderBottom: `1px solid ${colors.border}` }}
                          onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
                          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                        >
                          <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: colors.textPrimary, whiteSpace: "nowrap" }}>
                            {a.ip_address}
                          </td>
                          <td style={{ padding: "10px 12px", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                            {a.hostname || <span style={{ color: colors.textTertiary }}>—</span>}
                          </td>
                          <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                            {a.mac_address || <span style={{ color: colors.textTertiary }}>—</span>}
                          </td>
                          <td style={{ padding: "10px 12px", color: colors.textSecondary }}>
                            {a.os_fingerprint || <span style={{ color: colors.textTertiary }}>—</span>}
                          </td>
                          <td style={{ padding: "10px 12px", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                            {ports.length > 0 ? ports.join(", ") : <span style={{ color: colors.textTertiary }}>none</span>}
                          </td>
                          <td style={{ padding: "10px 12px", color: colors.textSecondary, fontSize: "12px" }}>
                            {Object.keys(services).length > 0
                              ? Object.entries(services).map(([port, name]) => `${port}: ${name}`).join(", ")
                              : <span style={{ color: colors.textTertiary }}>—</span>}
                          </td>
                          <td style={{ padding: "10px 12px", color: colors.textTertiary, whiteSpace: "nowrap" }}>
                            {a.last_seen && formatDistanceToNow(new Date(a.last_seen), { addSuffix: true })}
                          </td>
                          <td style={{ padding: "10px 12px", color: colors.textTertiary, textAlign: "right" }}>
                            {a.scan_count}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

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