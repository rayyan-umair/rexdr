/**
 * rexdr - Frontend
 * pages/EngineView.jsx - Per-engine detail page
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Updated : 2026-07-24 - Added an Active Chains panel for SIEM and a
 *           Cases panel for Response, since neither engine exposes a
 *           /detections endpoint - they were always stuck showing an
 *           empty "No detections yet" state regardless of how much
 *           real chain/case data existed. "Recent Detections" now
 *           only renders for engines that actually implement
 *           client.detections(). Case rows carry an onCaseClosed
 *           callback that bumps a refresh key so the list updates the
 *           moment a case is closed from the investigation blade.
 * Purpose : Single templated page that renders the detail view for
 *           whichever of the eight engines is active, based on the
 *           route param. Shows engine-specific stats, recent detections
 *           (or chains/cases where that's the more meaningful data),
 *           and the live stream scoped to that engine only. One
 *           component serves all eight engines rather than duplicating
 *           near-identical pages eight times.
 *
 * --- Part of the REXDR platform. ---
 */

import { useState } from "react";
import { useParams } from "react-router-dom";
import { AlertTriangle, Server, GitBranch, Briefcase, Users, Monitor } from "lucide-react";
import { colors, ENGINES } from "../design/tokens";
import { usePolling } from "../hooks/usePolling";
import { useLiveStream } from "../hooks/useLiveStream";
import { ENGINE_CLIENTS } from "../lib/api";
import StatTile from "../components/Shared/StatTile";
import SeverityBadge from "../components/Shared/SeverityBadge";
import EngineBadge from "../components/Shared/EngineBadge";
import EmptyState from "../components/Shared/EmptyState";
import InvestigationBlade from "../components/InvestigationBlade/InvestigationBlade";
import { formatDistanceToNow } from "date-fns";

function safeParse(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

const rowStyle = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  padding: "12px 14px",
  borderRadius: "8px",
  cursor: "pointer",
};

function StatusChip({ children, color }) {
  return (
    <span
      style={{
        fontSize: "10px",
        fontWeight: 700,
        letterSpacing: "0.04em",
        color,
        border: `1px solid ${color}55`,
        borderRadius: "4px",
        padding: "2px 6px",
        flexShrink: 0,
      }}
    >
      {children}
    </span>
  );
}

export default function EngineView({ onAskAI }) {
  const { engineId } = useParams();
  const engine = ENGINES[engineId];
  const client = ENGINE_CLIENTS[engineId];
  const [selected, setSelected] = useState(null);
  const [casesRefreshKey, setCasesRefreshKey] = useState(0);

  const { data: statsData } = usePolling(
    () => client.stats(),
    15000,
    [engineId]
  );

  const liveMessages = useLiveStream(engineId, 100);

  const hasDetectionsEndpoint = typeof client?.detections === "function";

  const { data: detectionsData } = usePolling(
    () => (hasDetectionsEndpoint ? client.detections(30) : Promise.resolve({ detections: [] })),
    20000,
    [engineId]
  );

  const isAssetDiscovery = engineId === "asset_discovery";
  const isSiem = engineId === "siem";
  const isResponse = engineId === "response";
  const isIdentity = engineId === "identity";

  const { data: assetsData } = usePolling(
    () => (isAssetDiscovery ? client.assets() : Promise.resolve({ assets: [] })),
    20000,
    [engineId]
  );

  const { data: entitiesData } = usePolling(
    () => (isIdentity ? client.entities(200) : Promise.resolve({ entities: [] })),
    20000,
    [engineId]
  );

  const { data: computersData } = usePolling(
    () => (isIdentity ? client.computers(500) : Promise.resolve({ computers: [] })),
    30000,
    [engineId]
  );

  const { data: chainsData } = usePolling(
    () => (isSiem ? client.chains(50, true) : Promise.resolve({ chains: [] })),
    15000,
    [engineId]
  );

  const { data: casesData } = usePolling(
    () => (isResponse ? client.cases(50) : Promise.resolve({ cases: [] })),
    15000,
    [engineId, casesRefreshKey]
  );

  if (!engine) {
    return <EmptyState icon={AlertTriangle} title="Unknown engine" />;
  }

  const stats = statsData?.stats || {};
  const detections = detectionsData?.detections || [];
  const assets = assetsData?.assets || [];
  const chains = chainsData?.chains || [];
  const cases = casesData?.cases || [];
  const entities = entitiesData?.entities || [];
  const computers = computersData?.computers || [];

  return (
    <div style={{ display: "flex", height: "100%" }}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflowY: "auto" }}>
        <div style={{ padding: "20px", borderBottom: `1px solid ${colors.border}` }}>
          <div style={{ fontSize: "18px", fontWeight: 700, color: colors.textPrimary, marginBottom: "4px" }}>
            {engine.label}
          </div>
          <div style={{ fontSize: "12px", color: colors.textTertiary, fontFamily: "'JetBrains Mono', monospace" }}>
            {engineId}
          </div>
        </div>

        <div style={{ display: "flex", gap: "12px", padding: "20px", flexWrap: "wrap" }}>
          {Object.entries(stats).map(([key, value]) => (
            <StatTile
              key={key}
              label={key.replace(/_/g, " ")}
              value={value}
              accentColor={
                key.includes("critical") && value > 0
                  ? colors.critical
                  : key.includes("open") && value > 0
                  ? colors.medium
                  : undefined
              }
            />
          ))}
        </div>

        {isAssetDiscovery && <AssetsPanel assets={assets} />}

        {isIdentity && <ComputersPanel computers={computers} />}

        {isIdentity && <EntitiesPanel entities={entities} />}

        {isSiem && (
          <ChainsPanel
            chains={chains}
            onSelect={(chain) => setSelected({ type: "attack_chain", data: chain, sourceEngine: engineId })}
          />
        )}

        {isResponse && (
          <CasesPanel
            cases={cases}
            onSelect={(c) =>
              setSelected({
                type: "case",
                data: c,
                sourceEngine: engineId,
                onCaseClosed: () => setCasesRefreshKey((k) => k + 1),
              })
            }
          />
        )}

        {hasDetectionsEndpoint && (
          <div style={{ padding: "0 20px 20px" }}>
            <div
              style={{
                fontSize: "12px",
                fontWeight: 700,
                color: colors.textTertiary,
                letterSpacing: "0.05em",
                marginBottom: "12px",
              }}
            >
              RECENT DETECTIONS
            </div>

            {detections.length === 0 ? (
              <EmptyState
                icon={AlertTriangle}
                title="No detections yet"
                description={`${engine.label} has not produced any detections in the current retention window.`}
              />
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
                {detections.map((d) => (
                  <div
                    key={d.detection_id}
                    onClick={() => setSelected({ type: "detection", data: d, sourceEngine: engineId })}
                    style={rowStyle}
                    onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <SeverityBadge severity={d.severity} size="sm" />
                    <span
                      style={{
                        fontSize: "11px",
                        color: colors.textTertiary,
                        fontFamily: "'JetBrains Mono', monospace",
                        flexShrink: 0,
                      }}
                    >
                      {d.detection_code}
                    </span>
                    <span
                      style={{
                        fontSize: "13px",
                        color: colors.textPrimary,
                        flex: 1,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {d.title}
                    </span>
                    <span style={{ fontSize: "11px", color: colors.textTertiary, flexShrink: 0 }}>
                      {d.timestamp && formatDistanceToNow(new Date(d.timestamp), { addSuffix: true })}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {selected && (
        <InvestigationBlade
          item={selected}
          onClose={() => setSelected(null)}
          onAskAI={onAskAI}
        />
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Asset Discovery - inventory table
// -----------------------------------------------------------------------------

function AssetsPanel({ assets }) {
  return (
    <div style={{ padding: "0 20px 20px" }}>
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          color: colors.textTertiary,
          letterSpacing: "0.05em",
          marginBottom: "12px",
        }}
      >
        DISCOVERED ASSETS
      </div>

      {assets.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No assets discovered yet"
          description="Discovered hosts will appear here once a scan cycle completes."
        />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${colors.border}` }}>
                {["IP Address", "Hostname", "MAC Address", "OS Fingerprint", "Open Ports", "Services", "Last Seen", "Scans"].map(
                  (h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "8px 12px",
                        fontSize: "11px",
                        fontWeight: 700,
                        color: colors.textTertiary,
                        letterSpacing: "0.03em",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => {
                const ports = safeParse(a.open_ports, []);
                const services = safeParse(a.services, {});
                return (
                  <tr
                    key={a.ip_address}
                    style={{ borderBottom: `1px solid ${colors.border}` }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: colors.textPrimary, whiteSpace: "nowrap" }}>
                      {a.ip_address}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                      {a.hostname || <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                      {a.mac_address || <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary }}>
                      {a.os_fingerprint || <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                      {ports.length > 0 ? ports.join(", ") : <span style={{ color: colors.textTertiary }}>none</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, fontSize: "12px" }}>
                      {Object.keys(services).length > 0
                        ? Object.entries(services).map(([port, name]) => `${port}: ${name}`).join(", ")
                        : <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textTertiary, whiteSpace: "nowrap" }}>
                      {a.last_seen && formatDistanceToNow(new Date(a.last_seen), { addSuffix: true })}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textTertiary, textAlign: "right" }}>
                      {a.scan_count}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// SIEM - active correlation chains
// -----------------------------------------------------------------------------

function ChainsPanel({ chains, onSelect }) {
  return (
    <div style={{ padding: "0 20px 20px" }}>
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          color: colors.textTertiary,
          letterSpacing: "0.05em",
          marginBottom: "12px",
        }}
      >
        ACTIVE CHAINS
      </div>

      {chains.length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title="No active chains"
          description="Cross-engine attack chains appear here when multiple engines correlate on the same entity."
        />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
          {chains.map((chain) => {
            const engines = safeParse(chain.contributing_engines, []);
            return (
              <div
                key={chain.chain_id}
                onClick={() => onSelect(chain)}
                style={rowStyle}
                onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <SeverityBadge severity={chain.severity} size="sm" />
                <StatusChip color={chain.is_active ? colors.critical : colors.textTertiary}>
                  {chain.is_active ? "ACTIVE" : chain.is_contained ? "CONTAINED" : "RESOLVED"}
                </StatusChip>
                <span
                  style={{
                    fontSize: "13px",
                    color: colors.textPrimary,
                    flex: 1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {chain.title}
                </span>
                <div style={{ display: "flex", gap: "4px", flexShrink: 0 }}>
                  {engines.map((e) => (
                    <EngineBadge key={e} engineId={e} />
                  ))}
                </div>
                <span style={{ fontSize: "11px", color: colors.textTertiary, flexShrink: 0 }}>
                  {chain.updated_at && formatDistanceToNow(new Date(chain.updated_at), { addSuffix: true })}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Response - incident case files
// -----------------------------------------------------------------------------

function CasesPanel({ cases, onSelect }) {
  return (
    <div style={{ padding: "0 20px 20px" }}>
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          color: colors.textTertiary,
          letterSpacing: "0.05em",
          marginBottom: "12px",
        }}
      >
        CASES
      </div>

      {cases.length === 0 ? (
        <EmptyState
          icon={Briefcase}
          title="No cases yet"
          description="Case files are generated automatically whenever a SIEM chain is confirmed."
        />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
          {cases.map((c) => (
            <div
              key={c.case_id}
              onClick={() => onSelect(c)}
              style={rowStyle}
              onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <SeverityBadge severity={c.severity} size="sm" />
              <StatusChip color={c.is_closed ? colors.textTertiary : colors.medium}>
                {c.is_closed ? "CLOSED" : "OPEN"}
              </StatusChip>
              <span
                style={{
                  fontSize: "13px",
                  color: colors.textPrimary,
                  flex: 1,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {c.title}
              </span>
              <span style={{ fontSize: "11px", color: colors.textTertiary, flexShrink: 0 }}>
                {c.created_at && formatDistanceToNow(new Date(c.created_at), { addSuffix: true })}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Identity - tracked account observations
// -----------------------------------------------------------------------------

function EntitiesPanel({ entities }) {
  return (
    <div style={{ padding: "0 20px 20px" }}>
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          color: colors.textTertiary,
          letterSpacing: "0.05em",
          marginBottom: "12px",
        }}
      >
        TRACKED ACCOUNTS
      </div>

      {entities.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No accounts tracked yet"
          description="Accounts appear here once the engine has processed authentication activity for them."
        />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${colors.border}` }}>
                {["Account", "Risk", "Events", "Detections", "Latest", "Known Groups", "Auth Hosts", "Last Seen"].map(
                  (h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "8px 12px",
                        fontSize: "11px",
                        fontWeight: 700,
                        color: colors.textTertiary,
                        letterSpacing: "0.03em",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {entities.map((e) => {
                const flags = safeParse(e.behavioral_flags, []);
                const groups = safeParse(e.known_groups, []);
                const hosts = safeParse(e.known_auth_hosts, []);
                const risk = Number(e.risk_contribution) || 0;

                return (
                  <tr
                    key={e.entity_id}
                    style={{ borderBottom: `1px solid ${colors.border}` }}
                    onMouseEnter={(ev) => (ev.currentTarget.style.background = colors.surface)}
                    onMouseLeave={(ev) => (ev.currentTarget.style.background = "transparent")}
                  >
                    <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: colors.textPrimary, whiteSpace: "nowrap" }}>
                      {e.entity_id}
                    </td>
                    <td style={{ padding: "10px 12px", whiteSpace: "nowrap" }}>
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontWeight: 700,
                          color: risk >= 0.7 ? colors.critical : risk > 0 ? colors.medium : colors.textTertiary,
                        }}
                      >
                        {risk.toFixed(2)}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, textAlign: "right" }}>
                      {e.event_count}
                    </td>
                    <td style={{ padding: "10px 12px", textAlign: "right", color: e.detection_count > 0 ? colors.critical : colors.textTertiary }}>
                      {e.detection_count}
                    </td>
                    <td style={{ padding: "10px 12px", whiteSpace: "nowrap" }}>
                      {e.latest_detection ? (
                        <span style={{ fontSize: "11px", fontFamily: "'JetBrains Mono', monospace", color: colors.textSecondary }}>
                          {e.latest_detection}
                        </span>
                      ) : (
                        <span style={{ color: colors.textTertiary }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, fontSize: "12px" }}>
                      {groups.length > 0 ? groups.join(", ") : <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, fontSize: "12px" }}>
                      {hosts.length > 0 ? (
                        <span title={hosts.join(", ")}>
                          {hosts.slice(0, 3).join(", ")}
                          {hosts.length > 3 ? ` +${hosts.length - 3}` : ""}
                        </span>
                      ) : (
                        <span style={{ color: colors.textTertiary }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textTertiary, whiteSpace: "nowrap" }}>
                      {e.last_seen && formatDistanceToNow(new Date(e.last_seen), { addSuffix: true })}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Identity - domain-joined computer objects
// -----------------------------------------------------------------------------

function ComputersPanel({ computers }) {
  return (
    <div style={{ padding: "0 20px 20px" }}>
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          color: colors.textTertiary,
          letterSpacing: "0.05em",
          marginBottom: "12px",
        }}
      >
        DOMAIN COMPUTERS
      </div>

      {computers.length === 0 ? (
        <EmptyState
          icon={Monitor}
          title="No domain computers enumerated yet"
          description="Domain-joined machines appear here after the next directory sync."
        />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${colors.border}` }}>
                {["Computer", "DNS Name", "Container", "Operating System", "Role", "Flags", "Last Logon"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 12px",
                      fontSize: "11px",
                      fontWeight: 700,
                      color: colors.textTertiary,
                      letterSpacing: "0.03em",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {computers.map((c) => {
                const flags = safeParse(c.uac_flags, []);
                // Unconstrained delegation is expected on a domain controller
                // and a credential theft vector anywhere else.
                const riskyDelegation = c.is_trusted_for_delegation && !c.is_domain_controller;

                return (
                  <tr
                    key={c.computer_name}
                    style={{ borderBottom: `1px solid ${colors.border}` }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = colors.surface)}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: colors.textPrimary, whiteSpace: "nowrap" }}>
                      {c.computer_name}
                      {!c.is_enabled && (
                        <span style={{ marginLeft: "6px", fontSize: "10px", fontWeight: 700, color: colors.textTertiary }}>
                          DISABLED
                        </span>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, fontSize: "12px", whiteSpace: "nowrap" }}>
                      {c.dns_hostname || <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary, whiteSpace: "nowrap" }}>
                      {c.container_path || <span style={{ color: colors.textTertiary }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textSecondary }}>
                      {c.operating_system || <span style={{ color: colors.textTertiary }}>—</span>}
                      {c.operating_system_version && (
                        <span style={{ color: colors.textTertiary, fontSize: "11px" }}> {c.operating_system_version}</span>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", whiteSpace: "nowrap" }}>
                      <span style={{ fontSize: "11px", fontWeight: 700, color: c.is_domain_controller ? colors.accent : colors.textTertiary }}>
                        {c.is_domain_controller ? "DOMAIN CONTROLLER" : "MEMBER"}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      {riskyDelegation ? (
                        <span
                          title="Unconstrained delegation on a non-DC allows this host to impersonate any user that authenticates to it."
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            color: colors.critical,
                            border: `1px solid ${colors.critical}55`,
                            borderRadius: "4px",
                            padding: "2px 6px",
                            whiteSpace: "nowrap",
                          }}
                        >
                          UNCONSTRAINED DELEGATION
                        </span>
                      ) : flags.length > 0 ? (
                        <span style={{ fontSize: "11px", color: colors.textTertiary }} title={flags.join(", ")}>
                          {flags.length} flag{flags.length !== 1 ? "s" : ""}
                        </span>
                      ) : (
                        <span style={{ color: colors.textTertiary }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px", color: colors.textTertiary, whiteSpace: "nowrap" }}>
                      {c.last_logon ? formatDistanceToNow(new Date(c.last_logon), { addSuffix: true }) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}