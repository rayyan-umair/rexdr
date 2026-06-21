/**
 * rexdr - Frontend
 * pages/NotFound.jsx - 404 fallback page
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Shown when a route doesn't match anything REXDR knows about.
 *           Plain, direct, points back to the overview rather than
 *           leaving the analyst stranded.
 *
 * --- Part of the REXDR platform. ---
 */

import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { colors } from "../design/tokens";

export default function NotFound() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: "16px",
      }}
    >
      <Compass size={32} color={colors.textTertiary} />
      <div style={{ fontSize: "15px", fontWeight: 600, color: colors.textPrimary }}>
        This page doesn't exist in REXDR.
      </div>
      <Link
        to="/"
        style={{
          fontSize: "13px",
          color: colors.accent,
          padding: "8px 16px",
          borderRadius: "8px",
          background: colors.accentSoft,
        }}
      >
        Back to Overview
      </Link>
    </div>
  );
}