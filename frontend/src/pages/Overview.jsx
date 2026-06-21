/**
 * rexdr - Frontend
 * pages/Overview.jsx - Platform landing dashboard
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : The first screen an analyst sees. Combines platform-wide
 *           stats, the live cross-engine alert stream, and the
 *           risk-sorted entity board into one operating view. This is
 *           where the "eight engines working as one platform" promise
 *           has to be felt immediately - not eight tabs, one picture.
 *
 * --- Part of the REXDR platform. ---
 */

import { useMemo, useState } from "react";
import { colors } from "../design/tokens";
import { useEngineHealth } from "../hooks/useEngineHealth";
import StatTile from "../components/Shared/StatTile";
import AlertStream from "../components/AlertStream/AlertStream";
import EntityRiskBoard from "../components/EntityRiskBoard/EntityRiskBoard";
import InvestigationBlade from "../components/InvestigationBlade/InvestigationBlade";

export default function Overview() {
  const { health } = useEngineHealth();
  const [selected, setSelected] = useState(null);
  const [activeTab, setActiveTab] = useState("alerts");

  const aggregateStats = useMemo(() => {
    const values = Object.values(health);
    const openDetections = values.reduce(
      (sum, h) => sum + (h?.stats?.open_detections || 0), 0
    );
    const criticalDetections = values.reduce(
      (sum, h) => sum + (h?.stats?.critical_detections || 0), 0
    );
    const activeChains = health?.siem?.stats?.active_chains || 0;
    const healthyEngines = values.filter((h) => h?.status === "healthy").length;

    return { openDetections, criticalDetections, activeChains, healthyEngines };
  }, [health]);

  return (
    <div style={{ display: "flex", height: "100%" }}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <div
          style={{
            display: "flex",
            gap: "12px",
            padding: "20px",
            borderBottom: `1px solid ${colors.border}`,
          }}
        >
          <StatTile label="Engines Online" value={`${aggregateStats.healthyEngines}/8`} />
          <StatTile
            label="Open Detections"
            value={aggregateStats.openDetections}
            accentColor={aggregateStats.openDetections > 0 ? colors.medium : undefined}
          />
          <StatTile
            label="Critical"
            value={aggregateStats.criticalDetections}
            accentColor={aggregateStats.criticalDetections > 0 ? colors.critical : undefined}
          />
          <StatTile
            label="Active Chains"
            value={aggregateStats.activeChains}
            accentColor={aggregateStats.activeChains > 0 ? colors.accent : undefined}
          />
        </div>

        <div
          style={{
            display: "flex",
            gap: "4px",
            padding: "12px 20px 0",
            borderBottom: `1px solid ${colors.border}`,
          }}
        >
          {[
            { id: "alerts", label: "Live Alerts" },
            { id: "entities", label: "Entity Risk Board" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: "10px 16px",
                fontSize: "13px",
                fontWeight: 600,
                color: activeTab === tab.id ? colors.textPrimary : colors.textTertiary,
                borderBottom: `2px solid ${activeTab === tab.id ? colors.accent : "transparent"}`,
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, overflow: "hidden" }}>
          {activeTab === "alerts" ? (
            <AlertStream onSelect={setSelected} />
          ) : (
            <div style={{ height: "100%", overflowY: "auto" }}>
              <EntityRiskBoard onSelectEntity={setSelected} />
            </div>
          )}
        </div>
      </div>

      {selected && (
        <InvestigationBlade
          item={selected}
          onClose={() => setSelected(null)}
          onAskAI={() => {}}
        />
      )}
    </div>
  );
}