import type { CSSProperties, ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Crosshair,
  Database,
  GitBranch,
  Globe2,
  Layers3,
  ShieldAlert,
  Target,
  TrendingUp,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Link } from "react-router-dom";

import {
  api,
  type Asset,
  type AttackPathsResponse,
  type PrioritiesResponse,
  type RiskSummary,
} from "./lib/api";

const severityOrder = ["Critical", "High", "Medium", "Low"] as const;

function formatPriorityLabel(priority: string) {
  return priority.charAt(0) + priority.slice(1).toLowerCase();
}

export default function CommandCenterPage() {
  const risk = useQuery({
    queryKey: ["risk-summary"],
    queryFn: api.riskSummary,
    refetchInterval: 30000,
  });

  const paths = useQuery({
    queryKey: ["attack-paths"],
    queryFn: api.attackPaths,
    refetchInterval: 30000,
  });

  const priorities = useQuery({
    queryKey: ["priorities"],
    queryFn: api.priorities,
    refetchInterval: 30000,
  });

  const assets = useQuery({
    queryKey: ["assets"],
    queryFn: api.assets,
    refetchInterval: 30000,
  });

  if (risk.isLoading || paths.isLoading || priorities.isLoading || assets.isLoading) {
    return (
      <div className="cc-state">
        <div className="cc-state-ring" />
        <strong>Preparing security posture</strong>
        <span>Loading environment intelligence and attack-surface context.</span>
      </div>
    );
  }

  if (risk.error || paths.error || priorities.error || assets.error) {
    return (
      <div className="cc-state">
        <AlertTriangle size={28} />
        <strong>Security posture unavailable</strong>
        <span>Singularity could not load the current environment intelligence.</span>
      </div>
    );
  }

  const riskData = risk.data as RiskSummary;
  const pathData = paths.data as AttackPathsResponse;
  const priorityData = priorities.data as PrioritiesResponse;
  const assetData = assets.data as Asset[];

  const criticalAssets = assetData.filter(
    (asset) => asset.criticality === "CRITICAL",
  ).length;

  const highValueAssets = assetData.filter(
    (asset) => asset.criticality === "HIGH" || asset.criticality === "CRITICAL",
  ).length;

  const exposedAssets = assetData.filter(
    (asset) => asset.internet_exposed,
  ).length;

  const topPriority = priorityData.results[0];

  const criticalPaths = pathData.paths.filter(
    (path) => path.target_criticality === "CRITICAL",
  ).length;
  const chartData = severityOrder.map((name) => ({
    name,
    value:
      name === "Critical" ? riskData.critical :
      name === "High" ? riskData.high :
      name === "Medium" ? riskData.medium :
      riskData.low,
  }));

  const riskScore = Math.round(riskData.overall_risk_score);
  const averageRisk = Math.round(riskData.average_risk_score);
  const riskState =
    riskScore >= 85 ? "Critical exposure" :
    riskScore >= 70 ? "High exposure" :
    riskScore >= 45 ? "Material exposure" :
    "Controlled exposure";

  return (
    <div className="cc-page">
      <div className="cc-field" aria-hidden="true">
        <div className="cc-field-grid" />
        <div className="cc-field-orbit cc-orbit-one" />
        <div className="cc-field-orbit cc-orbit-two" />
        <div className="cc-field-orbit cc-orbit-three" />
        <span className="cc-field-node cc-node-one" />
        <span className="cc-field-node cc-node-two" />
        <span className="cc-field-node cc-node-three" />
        <span className="cc-field-node cc-node-four" />
        <span className="cc-field-pulse cc-pulse-one" />
        <span className="cc-field-pulse cc-pulse-two" />
      </div>

      <section className="cc-hero">
        <div className="cc-hero-copy">
          <div className="cc-eyebrow">
            <Activity size={15} />
            Security Operations
          </div>

          <h2>
            Understand the
            <br />
            <span>risk surface.</span>
          </h2>

          <p>
            Singularity brings vulnerabilities, asset criticality and attack
            paths into one operational picture, so the team can see what
            deserves attention first.
          </p>

          <div className="cc-hero-actions">
            <Link to="/prioritization" className="cc-primary-action">
              Review priorities
              <ArrowRight size={16} />
            </Link>

            <Link to="/attack-paths" className="cc-secondary-action">
              Explore attack paths
              <GitBranch size={15} />
            </Link>
          </div>

          <div className="cc-hero-meta">
            <span>Environment analysis</span>
            <b>Continuous</b>
            <span className="cc-meta-separator" />
            <span>Contextual risk model</span>
            <b>Active</b>
          </div>
        </div>

        <div className="cc-risk-panel">
          <div className="cc-risk-header">
            <span>Overall risk</span>
            <span>{riskState}</span>
          </div>

          <div className="cc-risk-visual">
            <div
              className="cc-risk-ring"
              style={
                {
                  "--risk-progress": `${Math.min(riskScore, 100)}%`,
                } as CSSProperties
              }
            >
              <div className="cc-risk-ring-inner">
                <strong>{riskScore}</strong>
                <span>/ 100</span>
              </div>
            </div>

            <div className="cc-risk-side">
              <div>
                <span>Average finding risk</span>
                <strong>{averageRisk}</strong>
              </div>
              <div>
                <span>Critical targets</span>
                <strong>{criticalAssets}</strong>
              </div>
            </div>
          </div>

          <div className="cc-risk-foot">
            <span className="cc-risk-marker" />
            Risk is driven by current environment context
          </div>
        </div>
      </section>

      <section className="cc-command-strip">
        <div className="cc-strip-label">
          <span>Security decision layer</span>
          <strong>What matters right now</strong>
        </div>

        <div className="cc-strip-item">
          <span>Active attack paths</span>
          <strong>{pathData.path_count}</strong>
          <small>{criticalPaths} reach critical assets</small>
        </div>

        <div className="cc-strip-item">
          <span>Internet exposure</span>
          <strong>{exposedAssets}</strong>
          <small>externally reachable assets</small>
        </div>

        <div className="cc-strip-item">
          <span>Priority findings</span>
          <strong>{priorityData.count}</strong>
          <small>context-ranked findings</small>
        </div>

        <Link to="/investment" className="cc-strip-link">
          Model security investment
          <ArrowRight size={15} />
        </Link>
      </section>

      <section className="cc-kpi-grid">
        <Kpi
          icon={<Layers3 size={18} />}
          label="Assets in scope"
          value={assetData.length}
          detail={`${highValueAssets} high-value systems`}
        />
        <Kpi
          icon={<ShieldAlert size={18} />}
          label="Security findings"
          value={riskData.total_vulnerabilities}
          detail={`${riskData.critical} critical findings`}
        />
        <Kpi
          icon={<Target size={18} />}
          label="Critical assets"
          value={criticalAssets}
          detail={`${exposedAssets} currently internet-exposed`}
        />
        <Kpi
          icon={<TrendingUp size={18} />}
          label="Attack paths"
          value={pathData.path_count}
          detail={`${criticalPaths} reach critical targets`}
        />
      </section>

      <section className="cc-main-grid">
        <article className="cc-panel cc-priority-panel">
          <PanelHeader
            eyebrow="01 / DECISION PRIORITY"
            title="The actions most likely to reduce risk"
            description="Contextual ranking combines severity with the role each finding plays in your environment."
          />

          <div className="cc-priority-list">
            {priorityData.results.length === 0 ? (
              <div className="cc-empty">
                <Crosshair size={20} />
                <strong>No priority actions</strong>
                <span>There are no context-ranked findings in this environment.</span>
              </div>
            ) : (
              priorityData.results.slice(0, 5).map((item, index) => (
                <Link
                  to={`/prioritization/${item.vulnerability_id}`}
                  className="cc-priority-row"
                  key={item.vulnerability_id}
                >
                  <span className="cc-rank">{String(index + 1).padStart(2, "0")}</span>

                  <div className="cc-priority-body">
                    <span className="cc-priority-cve">{item.cve_id}</span>
                    <strong>{item.title}</strong>
                    <small>
                      {item.asset_name} · {item.attack_path_count} attack paths ·{" "}
                      {formatPriorityLabel(item.priority)} priority
                    </small>
                  </div>

                  <div className={`cc-score cc-score-${item.priority.toLowerCase()}`}>
                    {Math.round(item.risk_score)}
                  </div>

                  <ArrowRight className="cc-row-arrow" size={16} />
                </Link>
              ))
            )}
          </div>
        </article>

        <article className="cc-panel cc-chart-panel">
          <PanelHeader
            eyebrow="02 / FINDING PROFILE"
            title="Vulnerability distribution"
            description="Current findings grouped by contextual severity."
          />

          <div className="cc-chart-summary">
            <div>
              <strong>{riskData.total_vulnerabilities}</strong>
              <span>Total findings</span>
            </div>
            <div>
              <strong>{riskData.critical + riskData.high}</strong>
              <span>Critical + high</span>
            </div>
          </div>

          <div className="cc-chart">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 12, right: 8, left: -18, bottom: 4 }}>
                <CartesianGrid
                  stroke="rgba(145,173,204,.08)"
                  vertical={false}
                />
                <XAxis
                  dataKey="name"
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: "#74879c", fontSize: 11 }}
                />
                <YAxis
                  allowDecimals={false}
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: "#64778b", fontSize: 10 }}
                />
                <Tooltip
                  cursor={{ fill: "rgba(99,221,255,.035)" }}
                  contentStyle={{
                    background: "#08111c",
                    border: "1px solid rgba(99,221,255,.18)",
                    borderRadius: 4,
                    color: "#edf5f9",
                    fontSize: 11,
                  }}
                />
                <Bar
                  dataKey="value"
                  radius={[4, 4, 0, 0]}
                  fill="#63ddff"
                  maxBarSize={52}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>
      </section>

      <section className="cc-lower-grid">
        <article className="cc-panel cc-path-panel">
          <PanelHeader
            eyebrow="03 / ATTACK SURFACE"
            title="Most consequential paths"
            description="Routes that currently provide the clearest movement toward critical systems."
            action={
              <Link to="/attack-paths">
                View graph
                <ArrowRight size={14} />
              </Link>
            }
          />

          <div className="cc-path-list">
            {pathData.paths.slice(0, 4).map((path, index) => (
              <div className="cc-path-row" key={`${path.source_asset_id}-${path.target_asset_id}-${index}`}>
                <span className="cc-rank">{String(index + 1).padStart(2, "0")}</span>

                <div className="cc-path-main">
                  <div className="cc-path-chain">
                    {path.asset_names.map((name, assetIndex) => (
                      <span key={`${name}-${assetIndex}`}>
                        {name}
                        {assetIndex < path.asset_names.length - 1 && (
                          <ArrowRight size={13} />
                        )}
                      </span>
                    ))}
                  </div>
                  <small>
                    {path.vulnerabilities.length} vulnerability signals ·{" "}
                    {path.path_length} hops
                  </small>
                </div>

                <div className="cc-path-score">
                  {Math.round(path.risk_score)}
                  <span>risk</span>
                </div>
              </div>
            ))}

            {pathData.paths.length === 0 && (
              <div className="cc-empty">
                <GitBranch size={20} />
                <strong>No active attack paths</strong>
                <span>No modeled route currently reaches a critical target.</span>
              </div>
            )}
          </div>
        </article>

        <article className="cc-panel cc-insight-panel">
          <PanelHeader
            eyebrow="04 / SECURITY CONTEXT"
            title="Why the current posture matters"
            description="A concise readout of the environment signals driving the present risk."
          />

          <div className="cc-insight-stack">
            <InsightRow
              icon={<Globe2 size={17} />}
              label="External exposure"
              value={`${exposedAssets} assets`}
              text="Systems currently reachable from outside the trusted environment."
            />

            <InsightRow
              icon={<Database size={17} />}
              label="Critical concentration"
              value={`${criticalAssets} critical assets`}
              text="High-value systems that could amplify the impact of a compromise."
            />

            <InsightRow
              icon={<GitBranch size={17} />}
              label="Path concentration"
              value={`${pathData.path_count} modeled paths`}
              text={`${criticalPaths} of those paths currently terminate at critical assets.`}
            />
          </div>

          {topPriority && (
            <div className="cc-top-action">
              <span>Highest-priority action</span>
              <strong>{topPriority.cve_id}</strong>
              <small>
                {topPriority.title} on {topPriority.asset_name}
              </small>
              <Link to={`/prioritization/${topPriority.vulnerability_id}`}>
                Investigate finding
                <ArrowRight size={14} />
              </Link>
            </div>
          )}
        </article>
      </section>
    </div>
  );
}

function Kpi({
  icon,
  label,
  value,
  detail,
}: {
  icon: ReactNode;
  label: string;
  value: number;
  detail: string;
}) {
  return (
    <div className="cc-kpi">
      <div className="cc-kpi-icon">{icon}</div>
      <div className="cc-kpi-value">{value}</div>
      <div className="cc-kpi-label">{label}</div>
      <div className="cc-kpi-detail">{detail}</div>
    </div>
  );
}

function PanelHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="cc-panel-header">
      <div>
        <span className="cc-panel-eyebrow">{eyebrow}</span>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>

      {action && <div className="cc-panel-action">{action}</div>}
    </div>
  );
}

function InsightRow({
  icon,
  label,
  value,
  text,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  text: string;
}) {
  return (
    <div className="cc-insight-row">
      <div className="cc-insight-icon">{icon}</div>
      <div className="cc-insight-content">
        <span>{label}</span>
        <strong>{value}</strong>
        <p>{text}</p>
      </div>
    </div>
  );
}