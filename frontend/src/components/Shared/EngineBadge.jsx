/**
 * rexdr - Frontend
 * components/Shared/EngineBadge.jsx - Engine source indicator pill
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Shows which of the eight engines produced a given
 *           detection, event, or chain contribution. Used in the
 *           alert stream, investigation blade, and campaign timeline
 *           anywhere a piece of data needs to be attributed to its
 *           source engine.
 *
 * --- Part of the REXDR platform. ---
 */

import { colors, ENGINES } from "../../design/tokens";

export default function EngineBadge({ engineId, size = "md" }) {
  const engine = ENGINES[engineId] || { label: engineId, short: "?" };

  const sizeStyles = {
    sm: { padding: "2px 8px", fontSize: "10px" },
    md: { padding: "3px 10px", fontSize: "11px" },
  };

  return (
    <span
      title={engine.label}
      style={{
        display: "inline-flex",
        alignItems: "center",
        borderRadius: "6px",
        fontWeight: 600,
        letterSpacing: "0.05em",
        color: colors.textSecondary,
        background: colors.surfaceRaised,
        border: `1px solid ${colors.border}`,
        whiteSpace: "nowrap",
        ...sizeStyles[size],
      }}
    >
      {engine.short}
    </span>
  );
}