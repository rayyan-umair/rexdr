/**
 * rexdr - Frontend
 * components/Sidebar/Sidebar.jsx - Primary navigation sidebar
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Persistent left sidebar with engine navigation. Collapsed
 *           by default, expands on hover. Shows a live activity
 *           indicator and open-detection badge count per engine, pulled
 *           from health polling so the sidebar itself doubles as a
 *           lightweight status dashboard.
 *
 * --- Part of the REXDR platform. ---
 */

import { useState } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, MonitorCheck, Activity, GitMerge, Globe,
  Fingerprint, ShieldAlert, Radar, Bug, Settings,
} from "lucide-react";
import { colors, ENGINES } from "../../design/tokens";

const ICONS = {
  MonitorCheck, Activity, GitMerge, Globe, Fingerprint, ShieldAlert, Radar, Bug,
};

const NAV_ITEMS = [
  { path: "/", label: "Overview", icon: LayoutDashboard, engineId: null },
  ...Object.entries(ENGINES).map(([id, engine]) => ({
    path: `/engine/${id}`,
    label: engine.label,
    icon: ICONS[engine.icon],
    engineId: id,
  })),
];

export default function Sidebar({ health = {} }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
      style={{
        width: expanded ? "240px" : "64px",
        height: "100vh",
        background: colors.surface,
        borderRight: `1px solid ${colors.border}`,
        display: "flex",
        flexDirection: "column",
        transition: "width 0.18s ease",
        overflow: "hidden",
        flexShrink: 0,
        zIndex: 20,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "20px 18px",
          borderBottom: `1px solid ${colors.border}`,
          minHeight: "60px",
        }}
      >
        <div
          style={{
            width: "28px",
            height: "28px",
            borderRadius: "8px",
            background: colors.background,
            border: `1px solid ${colors.accent}55`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <span style={{ color: colors.accent, fontWeight: 800, fontSize: "13px" }}>R</span>
        </div>
        {expanded && (
          <span
            style={{
              fontWeight: 700,
              fontSize: "15px",
              letterSpacing: "0.02em",
              color: colors.textPrimary,
              whiteSpace: "nowrap",
            }}
          >
            REXDR
          </span>
        )}
      </div>

      <nav style={{ flex: 1, padding: "12px 8px", display: "flex", flexDirection: "column", gap: "2px" }}>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const engineHealth = item.engineId ? health[item.engineId] : null;
          const isHealthy = engineHealth?.status === "healthy";
          const openCount = engineHealth?.stats?.open_detections;

          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: "flex",
                alignItems: "center",
                gap: "12px",
                padding: "10px 12px",
                borderRadius: "8px",
                color: isActive ? colors.textPrimary : colors.textSecondary,
                background: isActive ? colors.surfaceRaised : "transparent",
                fontSize: "13px",
                fontWeight: isActive ? 600 : 500,
                whiteSpace: "nowrap",
                position: "relative",
              })}
            >
              <div style={{ position: "relative", flexShrink: 0, display: "flex" }}>
                <Icon size={18} />
                {item.engineId && (
                  <span
                    style={{
                      position: "absolute",
                      bottom: "-1px",
                      right: "-1px",
                      width: "7px",
                      height: "7px",
                      borderRadius: "999px",
                      background: isHealthy ? colors.success : colors.textTertiary,
                      border: `1.5px solid ${colors.surface}`,
                      animation: isHealthy ? "pulse-dot 2.4s ease-in-out infinite" : "none",
                    }}
                  />
                )}
              </div>
              {expanded && (
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {item.label}
                </span>
              )}
              {expanded && openCount > 0 && (
                <span
                  style={{
                    fontSize: "11px",
                    fontWeight: 700,
                    color: colors.critical,
                    background: colors.criticalSoft,
                    borderRadius: "999px",
                    padding: "1px 7px",
                    flexShrink: 0,
                  }}
                >
                  {openCount}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      <div style={{ padding: "12px 8px", borderTop: `1px solid ${colors.border}` }}>
        <NavLink
          to="/settings"
          style={({ isActive }) => ({
            display: "flex",
            alignItems: "center",
            gap: "12px",
            padding: "10px 12px",
            borderRadius: "8px",
            color: isActive ? colors.textPrimary : colors.textSecondary,
            background: isActive ? colors.surfaceRaised : "transparent",
            fontSize: "13px",
            fontWeight: 500,
            whiteSpace: "nowrap",
          })}
        >
          <Settings size={18} style={{ flexShrink: 0 }} />
          {expanded && <span>Settings</span>}
        </NavLink>
      </div>
    </div>
  );
}