/**
 * rexdr - Frontend
 * components/InvestigationBlade/InvestigationBlade.jsx - Slide-in investigation panel
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Updated : 2026-07-24 - Fixed MITRE tactic/technique rendering to match
 *           the real chain schema (mitre_tactics / mitre_techniques,
 *           plural, JSON-encoded arrays) instead of the singular fields
 *           that never actually existed on a chain object, so the
 *           MITRE section silently never rendered for a real chain.
 *           Fixed the WHEN section to fall back to created_at, since
 *           chains don't have a timestamp field. Added a CONTRIBUTING
 *           ENGINES section for chains. Added full case support -
 *           previously a "case" selection fell through to the generic
 *           detection view and rendered almost nothing useful. Cases
 *           now show status, entity, actions taken, the linked chain,
 *           and either the resolution (if closed) or a close-case
 *           form that calls the new POST /response/cases/{id}/close
 *           endpoint and updates the list via onCaseClosed.
 * Purpose : The core investigation experience. Slides in from the right
 *           when an alert, detection, chain, case, or entity is
 *           selected. Shows the full 5W+H context - what fired, why it
 *           matters, the entity's cross-engine history, and recommended
 *           next actions. This is what makes REXDR an investigation
 *           platform rather than a flat alert feed - every click here
 *           pulls together everything the platform knows about the
 *           selected item.
 *
 * --- Part of the REXDR platform. ---
 */

import { useState } from "react";
import { X, Clock, Target, AlertCircle, ListChecks, Sparkles, Layers, GitBranch, CheckCircle2, Check } from "lucide-react";
import { format } from "date-fns";
import { colors } from "../../design/tokens";
import { response, ENGINE_CLIENTS } from "../../lib/api";
import SeverityBadge from "../Shared/SeverityBadge";
import EngineBadge from "../Shared/EngineBadge";

function safeParseArray(value) {
  if (value == null) return [];
  if (Array.isArray(value)) return value;
  if (typeof value !== "string") return [value];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [value];
  }
}

export default function InvestigationBlade({ item, onClose, onAskAI, onDetectionTriaged }) {
  if (!item) return null;

  const data = item.data || item;
  const isChain = item.type === "attack_chain" || !!data.detection_ids || !!data.detections;
  const isCase = item.type === "case";
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
        ) : isCase ? (
          <CaseSection data={data} onCaseClosed={item.onCaseClosed} />
        ) : (
          <DetectionSection data={data} isChain={isChain} sourceEngine={item.sourceEngine} />
        )}
      </div>

      <div style={{ padding: "16px 20px", borderTop: `1px solid ${colors.border}`, display: "flex", flexDirection: "column", gap: "8px" }}>
        {!isChain && !isCase && !isEntity && data.detection_id && (
          <TriageButton
            detection={data}
            sourceEngine={item.sourceEngine}
            onTriaged={onDetectionTriaged}
          />
        )}
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
  const tactics = safeParseArray(data.mitre_tactics ?? data.mitre_tactic);
  const techniques = safeParseArray(data.mitre_techniques ?? data.mitre_technique);
  const contributingEngines = safeParseArray(data.contributing_engines);

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

      {contributingEngines.length > 0 && (
        <Section icon={Layers} label="CONTRIBUTING ENGINES">
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            {contributingEngines.map((e) => (
              <EngineBadge key={e} engineId={e} />
            ))}
          </div>
        </Section>
      )}

      {(tactics.length > 0 || techniques.length > 0) && (
        <Section icon={ListChecks} label="MITRE ATT&CK">
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            {tactics.map((t) => (
              <span
                key={`tactic-${t}`}
                style={{ fontSize: "12px", color: colors.textSecondary, background: colors.surfaceRaised, padding: "4px 10px", borderRadius: "6px" }}
              >
                {t}
              </span>
            ))}
            {techniques.map((t) => (
              <span
                key={`technique-${t}`}
                style={{
                  fontSize: "12px",
                  color: colors.textSecondary,
                  background: colors.surfaceRaised,
                  padding: "4px 10px",
                  borderRadius: "6px",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {t}
              </span>
            ))}
          </div>
        </Section>
      )}

      {(data.timestamp || data.created_at) && (
        <Section icon={Clock} label="WHEN">
          <div style={{ fontSize: "13px", color: colors.textSecondary }}>
            {format(new Date(data.timestamp || data.created_at), "MMM d, yyyy 'at' HH:mm:ss 'UTC'")}
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

function CaseSection({ data, onCaseClosed }) {
  const [localCase, setLocalCase] = useState(data);
  const [resolution, setResolution] = useState("");
  const [closing, setClosing] = useState(false);
  const [error, setError] = useState(null);

  const actionsTaken = safeParseArray(localCase.actions_taken);

  async function handleClose() {
    if (!resolution.trim()) {
      setError("Add a short resolution note before closing.");
      return;
    }

    setClosing(true);
    setError(null);

    try {
      await response.closeCase(localCase.case_id, resolution.trim());
      setLocalCase({
        ...localCase,
        is_closed: true,
        closed_at: new Date().toISOString(),
        resolution: resolution.trim(),
      });
      onCaseClosed?.();
    } catch (e) {
      setError(e.message || "Failed to close case.");
    } finally {
      setClosing(false);
    }
  }

  return (
    <>
      <div style={{ padding: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
          <SeverityBadge severity={localCase.severity} />
          <span
            style={{
              fontSize: "10px",
              fontWeight: 700,
              letterSpacing: "0.05em",
              color: localCase.is_closed ? colors.textTertiary : colors.medium,
            }}
          >
            {localCase.is_closed ? "CLOSED" : "OPEN"}
          </span>
        </div>
        <div style={{ fontSize: "17px", fontWeight: 700, color: colors.textPrimary, lineHeight: 1.3 }}>
          {localCase.title}
        </div>
      </div>

      {localCase.entity_id && (
        <Section icon={Target} label="ENTITY">
          <div
            style={{
              fontSize: "13px",
              fontWeight: 600,
              color: colors.textPrimary,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {localCase.entity_id}
          </div>
        </Section>
      )}

      <Section icon={Clock} label="OPENED">
        <div style={{ fontSize: "13px", color: colors.textSecondary }}>
          {localCase.created_at && format(new Date(localCase.created_at), "MMM d, yyyy 'at' HH:mm:ss 'UTC'")}
          {localCase.analyst ? ` — ${localCase.analyst}` : ""}
        </div>
      </Section>

      {actionsTaken.length > 0 && (
        <Section icon={ListChecks} label="ACTIONS TAKEN">
          <ul style={{ margin: 0, paddingLeft: "18px", display: "flex", flexDirection: "column", gap: "6px" }}>
            {actionsTaken.map((a, i) => (
              <li key={i} style={{ fontSize: "13px", color: colors.textSecondary, lineHeight: 1.5 }}>
                {a}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {localCase.chain_id && (
        <Section icon={GitBranch} label="LINKED CHAIN">
          <div style={{ fontSize: "12px", color: colors.textSecondary, fontFamily: "'JetBrains Mono', monospace" }}>
            {localCase.chain_id}
          </div>
        </Section>
      )}

      <Section icon={CheckCircle2} label="RESOLUTION">
        {localCase.is_closed ? (
          <div style={{ fontSize: "13px", color: colors.textSecondary, lineHeight: 1.6 }}>
            {localCase.resolution}
            <div style={{ fontSize: "11px", color: colors.textTertiary, marginTop: "6px" }}>
              Closed {localCase.closed_at && format(new Date(localCase.closed_at), "MMM d, yyyy 'at' HH:mm:ss 'UTC'")}
            </div>
          </div>
        ) : (
          <div>
            <textarea
              value={resolution}
              onChange={(e) => setResolution(e.target.value)}
              placeholder="What was done to resolve this? (required to close)"
              rows={3}
              style={{
                width: "100%",
                fontSize: "13px",
                fontFamily: "inherit",
                color: colors.textPrimary,
                background: colors.surfaceRaised,
                border: `1px solid ${colors.border}`,
                borderRadius: "8px",
                padding: "8px 10px",
                resize: "vertical",
                marginBottom: "8px",
                boxSizing: "border-box",
              }}
            />
            {error && (
              <div style={{ fontSize: "12px", color: colors.critical, marginBottom: "8px" }}>{error}</div>
            )}
            <button
              onClick={handleClose}
              disabled={closing}
              style={{
                width: "100%",
                padding: "10px",
                borderRadius: "8px",
                background: colors.surfaceRaised,
                border: `1px solid ${colors.critical}44`,
                color: colors.critical,
                fontSize: "13px",
                fontWeight: 600,
                cursor: closing ? "default" : "pointer",
              }}
            >
              {closing ? "Closing..." : "Close Case"}
            </button>
          </div>
        )}
      </Section>
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

function TriageButton({ detection, sourceEngine, onTriaged }) {
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState(detection.status === "false_positive");
  const [error, setError] = useState(null);

  async function markBenign() {
    const client = ENGINE_CLIENTS[sourceEngine];
    if (!client?.updateDetection) {
      setError("This engine does not support triage.");
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await client.updateDetection(detection.detection_id, "false_positive");
      setDone(true);
      onTriaged?.(detection.detection_id);
    } catch (e) {
      setError(e.message || "Could not update this detection.");
    } finally {
      setSaving(false);
    }
  }

  if (done) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: "8px",
          padding: "11px",
          borderRadius: "10px",
          background: `${colors.success}15`,
          border: `1px solid ${colors.success}44`,
          color: colors.success,
          fontSize: "13px",
          fontWeight: 600,
        }}
      >
        <Check size={15} />
        Marked benign
      </div>
    );
  }

  return (
    <div>
      <button
        onClick={markBenign}
        disabled={saving}
        title="Mark this detection as a false positive. It stays on record but drops out of open counts, the alert badge and the risk board."
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: "8px",
          padding: "11px",
          borderRadius: "10px",
          background: colors.surfaceRaised,
          border: `1px solid ${colors.success}44`,
          color: colors.success,
          fontSize: "13px",
          fontWeight: 600,
          cursor: saving ? "default" : "pointer",
        }}
      >
        <Check size={15} />
        {saving ? "Saving..." : "Mark benign"}
      </button>
      {error && (
        <div style={{ fontSize: "12px", color: colors.critical, marginTop: "6px" }}>{error}</div>
      )}
    </div>
  );
}