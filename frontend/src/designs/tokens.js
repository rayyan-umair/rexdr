/**
 * rexdr - Frontend
 * design/tokens.js - Design token system
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : The single source of truth for every color, font, spacing,
 *           and radius value used across the REXDR frontend. No component
 *           hardcodes a hex value or a magic number - everything pulls
 *           from here. This is what keeps the platform feeling like one
 *           coherent product instead of eight disconnected engine views.
 *
 * --- Part of the REXDR platform. ---
 */

export const colors = {
  // Surfaces
  background:     "#0A0A0C",
  surface:         "#13131A",
  surfaceRaised:   "#1A1A24",
  surfaceHover:    "#22222E",
  border:          "#26262F",
  borderStrong:    "#34343F",

  // Text
  textPrimary:     "#F4F4F8",
  textSecondary:   "#8E8EA3",
  textTertiary:    "#5C5C6C",

  // Accent
  accent:          "#00FFD1",
  accentDim:       "#00B89C",
  accentSoft:      "rgba(0, 255, 209, 0.12)",

  // Severity
  critical:        "#FF4D5E",
  criticalSoft:    "rgba(255, 77, 94, 0.14)",
  high:            "#FF9D4D",
  highSoft:        "rgba(255, 157, 77, 0.14)",
  medium:          "#FFD23F",
  mediumSoft:      "rgba(255, 210, 63, 0.14)",
  low:             "#5CA8FF",
  lowSoft:         "rgba(92, 168, 255, 0.14)",
  info:            "#8E8EA3",
  infoSoft:        "rgba(142, 142, 163, 0.14)",
  success:         "#3DDC84",
  successSoft:     "rgba(61, 220, 132, 0.14)",
};

export const severityColor = (severity) => {
  const map = {
    critical: colors.critical,
    high:     colors.high,
    medium:   colors.medium,
    low:      colors.low,
    info:     colors.info,
  };
  return map[severity?.toLowerCase()] || colors.info;
};

export const severitySoft = (severity) => {
  const map = {
    critical: colors.criticalSoft,
    high:     colors.highSoft,
    medium:   colors.mediumSoft,
    low:      colors.lowSoft,
    info:     colors.infoSoft,
  };
  return map[severity?.toLowerCase()] || colors.infoSoft;
};

export const fonts = {
  display: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  body:    "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  mono:    "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
};

export const radius = {
  sm: "6px",
  md: "10px",
  lg: "14px",
  full: "999px",
};

export const spacing = {
  xs: "4px",
  sm: "8px",
  md: "12px",
  lg: "16px",
  xl: "24px",
  xxl: "32px",
  xxxl: "48px",
};

export const shadow = {
  sm: "0 1px 2px rgba(0,0,0,0.4)",
  md: "0 4px 16px rgba(0,0,0,0.5)",
  lg: "0 8px 32px rgba(0,0,0,0.6)",
  glow: "0 0 24px rgba(0,255,209,0.18)",
};

export const ENGINES = {
  windows_event:    { label: "Windows Event",      short: "WIN",  icon: "MonitorCheck" },
  network_flow:     { label: "Network Flow",        short: "NET",  icon: "Activity" },
  siem:             { label: "SIEM Correlation",     short: "SIEM", icon: "GitMerge" },
  dns:              { label: "DNS Behavioral",       short: "DNS",  icon: "Globe" },
  identity:         { label: "Active Directory",     short: "AD",   icon: "Fingerprint" },
  response:         { label: "Incident Response",    short: "IR",   icon: "ShieldAlert" },
  asset_discovery:  { label: "Network Discovery",    short: "DISC", icon: "Radar" },
  vulnerability:    { label: "Vulnerability Intel",   short: "VULN", icon: "Bug" },
};

export const ENGINE_PORTS = {
  windows_event:   8000,
  network_flow:    8001,
  siem:            8002,
  dns:             8003,
  identity:        8004,
  response:        8005,
  asset_discovery: 8006,
  vulnerability:   8007,
};