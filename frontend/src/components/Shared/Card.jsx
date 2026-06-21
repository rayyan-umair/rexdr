/**
 * rexdr - Frontend
 * components/Shared/Card.jsx - Base surface container
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : The base card/panel surface used throughout REXDR -
 *           detection rows, stat tiles, the investigation blade
 *           sections. Keeps border, radius, and background consistent
 *           platform-wide without every view redefining the same
 *           container styles.
 *
 * --- Part of the REXDR platform. ---
 */

import { colors, radius } from "../../design/tokens";

export default function Card({
  children,
  padding = "16px",
  hoverable = false,
  onClick,
  style = {},
}) {
  return (
    <div
      onClick={onClick}
      style={{
        background: colors.surface,
        border: `1px solid ${colors.border}`,
        borderRadius: radius.md,
        padding,
        transition: "border-color 0.15s ease, background 0.15s ease",
        cursor: onClick ? "pointer" : "default",
        ...style,
      }}
      onMouseEnter={(e) => {
        if (hoverable || onClick) {
          e.currentTarget.style.borderColor = colors.borderStrong;
          e.currentTarget.style.background = colors.surfaceRaised;
        }
      }}
      onMouseLeave={(e) => {
        if (hoverable || onClick) {
          e.currentTarget.style.borderColor = colors.border;
          e.currentTarget.style.background = colors.surface;
        }
      }}
    >
      {children}
    </div>
  );
}