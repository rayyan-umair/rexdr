/**
 * rexdr - Frontend
 * components/CommandPalette/CommandPalette.jsx - Global Cmd+K search
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Modal command palette triggered from the TopBar search bar
 *           or Cmd+K. Lets an analyst jump straight to an engine view
 *           or settings without navigating the sidebar. Kept simple by
 *           design - this is navigation, not a search index over live
 *           detection data, which belongs in a dedicated search feature
 *           later if needed.
 *
 * --- Part of the REXDR platform. ---
 */

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search, LayoutDashboard, Settings as SettingsIcon } from "lucide-react";
import { colors, ENGINES } from "../../design/tokens";

export default function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  const items = useMemo(() => {
    const base = [
      { label: "Overview", path: "/", icon: LayoutDashboard },
      ...Object.entries(ENGINES).map(([id, engine]) => ({
        label: engine.label,
        path: `/engine/${id}`,
        icon: null,
        short: engine.short,
      })),
      { label: "Settings", path: "/settings", icon: SettingsIcon },
    ];

    if (!query.trim()) return base;
    const q = query.toLowerCase();
    return base.filter((i) => i.label.toLowerCase().includes(q));
  }, [query]);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") onClose?.();
    };
    if (open) window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "14vh",
        zIndex: 100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "560px",
          maxWidth: "90vw",
          background: colors.surfaceRaised,
          border: `1px solid ${colors.borderStrong}`,
          borderRadius: "14px",
          boxShadow: "0 16px 48px rgba(0,0,0,0.6)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            padding: "14px 16px",
            borderBottom: `1px solid ${colors.border}`,
          }}
        >
          <Search size={16} color={colors.textTertiary} />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to an engine, page, or setting..."
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              fontSize: "14px",
              color: colors.textPrimary,
            }}
          />
        </div>

        <div style={{ maxHeight: "320px", overflowY: "auto", padding: "6px" }}>
          {items.length === 0 ? (
            <div style={{ padding: "20px", textAlign: "center", fontSize: "13px", color: colors.textTertiary }}>
              No matches for "{query}"
            </div>
          ) : (
            items.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.path}
                  onClick={() => {
                    navigate(item.path);
                    onClose?.();
                  }}
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "10px 12px",
                    borderRadius: "8px",
                    fontSize: "13px",
                    color: colors.textPrimary,
                    textAlign: "left",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = colors.surfaceHover)}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  {Icon ? (
                    <Icon size={15} color={colors.textTertiary} />
                  ) : (
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: 700,
                        color: colors.textTertiary,
                        width: "15px",
                        textAlign: "center",
                      }}
                    >
                      {item.short}
                    </span>
                  )}
                  {item.label}
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}