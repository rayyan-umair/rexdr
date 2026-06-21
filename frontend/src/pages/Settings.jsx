/**
 * rexdr - Frontend
 * pages/Settings.jsx - Platform configuration view
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Shows the AI provider configuration status and links to
 *           the Tkinter launcher for actual config changes. The web
 *           frontend is read-only for sensitive config like credentials
 *           and targets - those are edited through the launcher, which
 *           runs locally on the REXDR host. This page surfaces status,
 *           not a duplicate editing surface.
 *
 * --- Part of the REXDR platform. ---
 */

import { Sparkles, Network, ShieldCheck } from "lucide-react";
import { colors } from "../design/tokens";
import Card from "../components/Shared/Card";

export default function Settings() {
  return (
    <div style={{ padding: "32px", maxWidth: "640px", overflowY: "auto", height: "100%" }}>
      <div style={{ fontSize: "20px", fontWeight: 700, color: colors.textPrimary, marginBottom: "6px" }}>
        Settings
      </div>
      <div style={{ fontSize: "13px", color: colors.textTertiary, marginBottom: "28px" }}>
        Configuration for credentials, network targets, and zones is managed
        through the REXDR Tkinter launcher on the host machine, not from this
        browser view.
      </div>

      <Section icon={Sparkles} title="AI Investigation Assistant">
        Configure your AI provider - Groq, OpenAI, Anthropic, Gemini, or Ollama
        for fully air-gapped deployments - in the launcher's configuration
        wizard. Once set, the AI panel becomes available across every
        investigation view.
      </Section>

      <Section icon={Network} title="Network Targets and Zones">
        Domain controllers, staff workstations, and network zone CIDR ranges
        are defined in <code style={{ color: colors.accent }}>targets.yaml</code> and{" "}
        <code style={{ color: colors.accent }}>zones.yaml</code>. Edit these through
        the launcher's targets editor, which validates the file before REXDR
        reloads it.
      </Section>

      <Section icon={ShieldCheck} title="Response Automation">
        Auto-containment thresholds for critical and high severity attack
        chains are configured per-deployment. Review active playbooks under
        the Incident Response engine view.
      </Section>
    </div>
  );
}

function Section({ icon: Icon, title, children }) {
  return (
    <Card style={{ marginBottom: "16px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
        <Icon size={16} color={colors.accent} />
        <span style={{ fontSize: "14px", fontWeight: 600, color: colors.textPrimary }}>{title}</span>
      </div>
      <div style={{ fontSize: "13px", color: colors.textSecondary, lineHeight: 1.6 }}>{children}</div>
    </Card>
  );
}