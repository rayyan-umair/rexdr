/**
 * rexdr - Frontend
 * components/Shared/SeverityBadge.jsx - Severity indicator pill
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : The single severity badge component used everywhere a
 *           detection, alert, or chain severity needs to be shown.
 *           Every severity color in the platform traces back to this
 *           one component reading from design tokens - no view
 *           hardcodes its own severity colors.
 *
 * --- Part of the REXDR platform. ---
 */

import { severityColor, severitySoft } from "../../design/tokens";

export default function SeverityBadge({ severity, size = "md" }) {
  const label = (severity || "info").toUpperCase();
  const color = severityColor(severity);
  const bg = severitySoft(severity);

  const sizeStyles = {
    sm: { padding: "2px 8px", fontSize: "11px" },
    md: { padding: "3px 10px", fontSize: "12px" },
    lg: { padding: "4px 12px", fontSize: "13px" },
  };

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        borderRadius: "999px",
        fontWeight: 600,
        letterSpacing: "0.04em",
        color,
        background: bg,
        border: `1px solid ${color}33`,
        whiteSpace: "nowrap",
        ...sizeStyles[size],
      }}
    >
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "999px",
          background: color,
          flexShrink: 0,
        }}
      />
      {label}
    </span>
  );
}