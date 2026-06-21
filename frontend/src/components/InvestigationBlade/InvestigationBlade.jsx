/**
 * rexdr - Frontend
 * components/InvestigationBlade/InvestigationBlade.jsx - Slide-in investigation panel
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : The core investigation experience. Slides in from the right
 *           when an alert, detection, or entity is selected. Shows the
 *           full 5W+H context - what fired, why it matters, the entity's
 *           cross-engine history, and recommended next actions. This is
 *           what makes REXDR an investigation platform rather than a
 *           flat alert feed - every click here pulls together everything
 *           the platform knows about the selected item.
 *
 * --- Part of the REXDR platform. ---
 */

import { X, Clock, Target, AlertCircle, ListChecks, Sparkles } from "lucide-react";
import { format } from "date-fns";
import { colors } from "../../design/tokens";
import SeverityBadge from "../Shared/SeverityBadge";
import EngineBadge from "../Shared/EngineBadge";

export default function InvestigationBlade({ item, onClose, onAskAI }) {
  if (!item) return null;

  const data = item.data || item;
  const isChain = item.type === "attack_chain" || data.detections;
  const isEntity = !!data.entityId;

  return (
    <div
      style={{
        width: "420px",
        height: "100%",
        background: colors.surface,
        borderLeft: `1px solid ${colors.border}`,
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        animation: "slide-in-right 0.18s ease",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "16px 20px",
          borderBottom: `1px solid ${colors.border}`,
        }}
      >
        <span style={{ fontSize: "12px", fontWeight: 700, color: colors.textTertiary, letterSpacing: "0.05em" }}>
          INVESTIGATION
        </span>
        <button
          onClick={onClose}
          style={{
            width: "28px",
            height: "28px",
            borderRadius: "6px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: colors.textTertiary,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = colors.surfaceRaised)}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          <X size={16} />
        </button>
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        {isEntity ? (
          <EntitySection entity={data} />
        ) : (
          <DetectionSection data={data} isChain={isChain} sourceEngine={item.sourceEngine} />
        )}
      </div>

      <div style={{ padding: "16px 20px", borderTop: `1px solid ${colors.border}` }}>
        <button
          onClick={() => onAskAI?.(item)}
          style={{
            width: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            padding: "11px",
            borderRadius: "10px",
            background: colors.accentSoft,
            border: `1px solid ${colors.accent}44`,
            color: colors.accent,
            fontSize: "13px",
            fontWeight: 600,
          }}
        >
          <Sparkles size={15} />
          Ask AI to explain this
        </button>
      </div>
    </div>
  );
}

function Section({ icon: Icon, label, children }) {
  return (
    <div style={{ padding: "18px 20px", borderBottom: `1px solid ${colors.border}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px" }}>
        <Icon size={13} color={colors.textTertiary} />
        <span
          style={{
            fontSize: "11px",
            fontWeight: 700,
            color: colors.textTertiary,
            letterSpacing: "0.05em",
          }}
        >
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

function DetectionSection({ data, isChain, sourceEngine }) {
  return (
    <>
      <div style={{ padding: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
          {isChain && (
            <span style={{ fontSize: "10px", fontWeight: 700, color: colors.accent, letterSpacing: "0.05em" }}>
              ATTACK CHAIN
            </span>
          )}
          <SeverityBadge severity={data.severity} />
          {sourceEngine && <EngineBadge engineId={sourceEngine} />}
        </div>
        <div style={{ fontSize: "17px", fontWeight: 700, color: colors.textPrimary, lineHeight: 1.3 }}>
          {data.title || data.rule_title}
        </div>
      </div>

      {data.description && (
        <Section icon={AlertCircle} label="WHAT HAPPENED">
          <div style={{ fontSize: "13px", color: colors.textSecondary, lineHeight: 1.6 }}>
            {data.description}
          </div>
        </Section>
      )}

      {data.entity_id && (
        <Section icon={Target} label="ENTITY">
          <div
            style={{
              fontSize: "13px",
              fontWeight: 600,
              color: colors.textPrimary,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {data.entity_id}
          </div>
        </Section>
      )}

      {(data.mitre_tactic || data.mitre_technique) && (
        <Section icon={ListChecks} label="MITRE ATT&CK">
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {data.mitre_tactic && (
              <span style={{ fontSize: "12px", color: colors.textSecondary, background: colors.surfaceRaised, padding: "4px 10px", borderRadius: "6px" }}>
                {data.mitre_tactic}
              </span>
            )}
            {data.mitre_technique && (
              <span style={{ fontSize: "12px", color: colors.textSecondary, background: colors.surfaceRaised, padding: "4px 10px", borderRadius: "6px", fontFamily: "'JetBrains Mono', monospace" }}>
                {data.mitre_technique}
              </span>
            )}
          </div>
        </Section>
      )}

      {data.timestamp && (
        <Section icon={Clock} label="WHEN">
          <div style={{ fontSize: "13px", color: colors.textSecondary }}>
            {format(new Date(data.timestamp), "MMM d, yyyy 'at' HH:mm:ss 'UTC'")}
          </div>
        </Section>
      )}

      {data.narrative && (
        <Section icon={ListChecks} label="INVESTIGATION NARRATIVE">
          <div style={{ fontSize: "12px", color: colors.textSecondary, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
            {data.narrative}
          </div>
        </Section>
      )}
    </>
  );
}

function EntitySection({ entity }) {
  return (
    <>
      <div style={{ padding: "20px" }}>
        <div
          style={{
            fontSize: "17px",
            fontWeight: 700,
            color: colors.textPrimary,
            fontFamily: "'JetBrains Mono', monospace",
            marginBottom: "8px",
          }}
        >
          {entity.entityId}
        </div>
        <SeverityBadge severity={entity.highestSeverity} />
      </div>

      <Section icon={Target} label="OBSERVED BY">
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
          {Array.from(entity.engines || []).map((e) => (
            <EngineBadge key={e} engineId={e} />
          ))}
        </div>
      </Section>

      <Section icon={AlertCircle} label="ACTIVITY">
        <div style={{ fontSize: "13px", color: colors.textSecondary }}>
          {entity.detectionCount} detection{entity.detectionCount !== 1 ? "s" : ""} across{" "}
          {entity.engineCount} engine{entity.engineCount !== 1 ? "s" : ""}
        </div>
      </Section>

      {entity.lastSeen && (
        <Section icon={Clock} label="LAST SEEN">
          <div style={{ fontSize: "13px", color: colors.textSecondary }}>
            {format(new Date(entity.lastSeen), "MMM d, yyyy 'at' HH:mm:ss 'UTC'")}
          </div>
        </Section>
      )}
    </>
  );
}