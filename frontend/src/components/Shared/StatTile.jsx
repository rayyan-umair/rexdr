/**
 * rexdr - Frontend
 * components/Shared/StatTile.jsx - Single metric display tile
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Displays one key metric with a label, value, and optional
 *           trend or accent color. Used across every engine's overview
 *           row - total events, open detections, active chains, asset
 *           counts, and similar single-number summaries.
 *
 * --- Part of the REXDR platform. ---
 */

import { colors } from "../../design/tokens";
import Card from "./Card";

export default function StatTile({ label, value, accentColor, suffix = "" }) {
  return (
    <Card padding="14px 16px" style={{ flex: 1, minWidth: "120px" }}>
      <div
        style={{
          fontSize: "11px",
          fontWeight: 600,
          letterSpacing: "0.04em",
          color: colors.textTertiary,
          textTransform: "uppercase",
          marginBottom: "8px",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: "26px",
          fontWeight: 700,
          color: accentColor || colors.textPrimary,
          lineHeight: 1,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        {value}
        {suffix && (
          <span style={{ fontSize: "14px", color: colors.textTertiary, marginLeft: "4px" }}>
            {suffix}
          </span>
        )}
      </div>
    </Card>
  );
}