/**
 * rexdr - Frontend
 * components/Shared/EmptyState.jsx - Empty and loading state display
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Consistent empty-state messaging across every view. An
 *           empty screen is an invitation to act, not a dead end - this
 *           component always explains what's missing and why, in the
 *           platform's voice rather than a generic placeholder.
 *
 * --- Part of the REXDR platform. ---
 */

import { colors } from "../../design/tokens";

export default function EmptyState({ icon: Icon, title, description }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "64px 24px",
        textAlign: "center",
        color: colors.textSecondary,
      }}
    >
      {Icon && (
        <div
          style={{
            width: "48px",
            height: "48px",
            borderRadius: "12px",
            background: colors.surfaceRaised,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            marginBottom: "16px",
          }}
        >
          <Icon size={22} color={colors.textTertiary} />
        </div>
      )}
      <div style={{ fontSize: "14px", fontWeight: 600, color: colors.textPrimary, marginBottom: "4px" }}>
        {title}
      </div>
      {description && (
        <div style={{ fontSize: "13px", color: colors.textTertiary, maxWidth: "320px" }}>
          {description}
        </div>
      )}
    </div>
  );
}