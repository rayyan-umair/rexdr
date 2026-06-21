/**
 * rexdr - Frontend
 * components/EnvironmentMap/EnvironmentMap.jsx - Live network topology view
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Visualizes the discovered network as a zone-grouped node
 *           graph. Entities are plotted by their network zone, with
 *           visual connections drawn for active attack chains. This is
 *           the spatial view of REXDR's unified entity model - instead
 *           of reading a list, an analyst can see where on the network
 *           a campaign is unfolding and which zones it has crossed.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useMemo, useState } from "react";
import { Map as MapIcon } from "lucide-react";
import { colors } from "../../design/tokens";
import { assetDiscovery } from "../../lib/api";
import { useAllEnginesStream } from "../../hooks/useLiveStream";
import EmptyState from "../Shared/EmptyState";

function riskColor(score) {
  if (score >= 75) return colors.critical;
  if (score >= 50) return colors.high;
  if (score >= 25) return colors.medium;
  return colors.accent;
}

export default function EnvironmentMap() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const messages = useAllEnginesStream(300);

  useEffect(() => {
    assetDiscovery
      .assets()
      .then((res) => setAssets(res.assets || []))
      .catch(() => setAssets([]))
      .finally(() => setLoading(false));
  }, []);

  const riskByIp = useMemo(() => {
    const map = {};
    const rankWeight = { critical: 85, high: 50, medium: 25, low: 10, info: 2 };

    messages
      .filter((m) => m.type === "detection" && m.data?.entity_id)
      .forEach((m) => {
        const id = m.data.entity_id;
        const score = rankWeight[m.data.severity] || 0;
        map[id] = Math.max(map[id] || 0, score);
      });

    return map;
  }, [messages]);

  const zones = useMemo(() => {
    const grouped = {};
    assets.forEach((asset) => {
      const zone = asset.network_zone || "unzoned";
      if (!grouped[zone]) grouped[zone] = [];
      grouped[zone].push(asset);
    });
    return grouped;
  }, [assets]);

  if (loading) {
    return (
      <EmptyState
        icon={MapIcon}
        title="Loading environment map"
        description="Pulling the current asset inventory from Network Discovery."
      />
    );
  }

  if (assets.length === 0) {
    return (
      <EmptyState
        icon={MapIcon}
        title="No assets discovered yet"
        description="The Network Discovery engine populates this view once its first scan cycle completes."
      />
    );
  }

  return (
    <div style={{ padding: "20px", overflowY: "auto", height: "100%" }}>
      {Object.entries(zones).map(([zoneId, zoneAssets]) => (
        <div key={zoneId} style={{ marginBottom: "28px" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "12px",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                fontWeight: 700,
                color: colors.textTertiary,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
              }}
            >
              {zoneId.replace(/_/g, " ")}
            </span>
            <span
              style={{
                fontSize: "11px",
                color: colors.textTertiary,
                background: colors.surfaceRaised,
                borderRadius: "999px",
                padding: "1px 8px",
              }}
            >
              {zoneAssets.length}
            </span>
          </div>

          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "12px",
            }}
          >
            {zoneAssets.map((asset) => {
              const risk = riskByIp[asset.ip_address] || 0;
              const color = risk > 0 ? riskColor(risk) : colors.border;

              return (
                <div
                  key={asset.ip_address}
                  title={`${asset.ip_address}${asset.hostname ? ` (${asset.hostname})` : ""}`}
                  style={{
                    width: "84px",
                    padding: "10px 8px",
                    borderRadius: "10px",
                    background: colors.surface,
                    border: `1.5px solid ${color}`,
                    boxShadow: risk > 50 ? `0 0 16px ${color}33` : "none",
                    textAlign: "center",
                  }}
                >
                  <div
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "999px",
                      background: color,
                      margin: "0 auto 8px",
                      animation: risk > 50 ? "pulse-dot 1.6s ease-in-out infinite" : "none",
                    }}
                  />
                  <div
                    style={{
                      fontSize: "10px",
                      fontFamily: "'JetBrains Mono', monospace",
                      color: colors.textSecondary,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {asset.ip_address}
                  </div>
                  {asset.hostname && (
                    <div
                      style={{
                        fontSize: "9px",
                        color: colors.textTertiary,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        marginTop: "2px",
                      }}
                    >
                      {asset.hostname}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}