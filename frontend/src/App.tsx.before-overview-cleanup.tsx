import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  ChevronRight,
  CircleDot,
  Crosshair,
  Database,
  Gauge,
  GitBranch,
  Globe,
  LayoutDashboard,
  LockKeyhole,
  Network,
  PackageSearch,
  Radar,
  Search,
  Server,
  Settings,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  Upload,
  Wifi,
  Zap,
} from "lucide-react";

import {
  Background,
  Controls,
  MiniMap,
  MarkerType,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

import {
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar,
} from "recharts";

import {
  BrowserRouter,
  Link,
  NavLink,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { clearSession, getStoredUser } from "./lib/auth";

import { useQuery } from "@tanstack/react-query";

import VulnerabilityDetailPage from "./VulnerabilityDetailPage";
import PrioritizationComparisonPage from "./PrioritizationComparisonPage";
import AddAssetModal from "./AddAssetModal";
import AttackPathDetailPage from "./AttackPathDetailPage";
import ThreatIntelligencePage from "./ThreatIntelligencePage";
import TopSecurityAction from "./TopSecurityAction";
import EnvironmentImportPage from "./EnvironmentImportPage";
import InvestmentOptimizerPage from "./InvestmentOptimizerPage";
import CommandCenterPage from "./CommandCenterPage";
import {
  api,
  type Asset,
  type AttackPathsResponse,
  type NetworkGraphResponse,
  type PrioritiesResponse,
  type PriorityResult,
  type RiskSummary,
} from "./lib/api";

import LandingPage from "./LandingPage";
import AuthPage from "./AuthPage";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/auth" element={<AuthPage />} />
        <Route path="/*" element={<AppShell />} />
      </Routes>
    </BrowserRouter>
  );
}

const navGroups = [
  {
    label: "Overview",
    items: [
      

    ],
  },
  {
    label: "Overview",
    items: [
      {
        to: "/CommandCenter",
        label: "Command Center",
        icon: LayoutDashboard,
      },
    ],
  },  {
    label: "Attack Surface",
    items: [
      {
        to: "/assets",
        label: "Assets",
        icon: Server,
      },
    ],
  },
  {
    label: "Risk Intelligence",
    items: [
      {
        to: "/vulnerabilities",
        label: "Vulnerabilities",
        icon: ShieldAlert,
      },
      {
        to: "/prioritization",
        label: "Prioritization",
        icon: Radar,
      },
      {
        to: "/attack-paths",
        label: "Attack Paths",
        icon: GitBranch,
      },
    ],
  },
  {
    label: "Operations",
    items: [
      {
        to: "/investment",
        label: "Investment Optimizer",
        icon: Sparkles,
      },

      {
        to: "/threat-intel",
        label: "Threat Intelligence",
        icon: Activity,
      },
      {
        to: "/import",
        label: "Import Environment",
        icon: Upload,
      },
      {
        to: "/remediation",
        label: "Remediation",
        icon: Crosshair,
      },      
      
      {
        to: "/settings",
        label: "Settings",
        icon: Settings,
      },
    ],
  },
];

function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const user = getStoredUser();

  const title = (() => {
    if (location.pathname === "/CommandCenter") {
      return "Command Center";
    }

    if (location.pathname === "/assets") {
      return "Attack Surface";
    }


    if (location.pathname === "/vulnerabilities") {
      return "Vulnerability Intelligence";
    }

    if (location.pathname === "/prioritization") {
      return "Risk Prioritization";
    }

    if (
      location.pathname === "/prioritization/comparison"
    ) {
      return "CVSS vs Singularity";
    }

    if (
      location.pathname.startsWith("/prioritization/")
    ) {
      return "Vulnerability Investigation";
    }

    if (location.pathname === "/attack-paths") {
      return "Attack Path Analysis";
    }

    if (location.pathname === "/remediation") {
      return "Remediation";
    }

    if (location.pathname === "/threat-intel") {
      return "Threat Intelligence";
    }

    if (location.pathname === "/import") {
      return "Import Environment";
    }

    if (location.pathname === "/investment") {
      return "Investment Optimizer";
    }

    if (location.pathname === "/settings") {
      return "Settings";
    }

    return "Singularity";
  })();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <span className="brand-glyph">S</span>
            <span className="brand-orbit brand-orbit-a" />
            <span className="brand-orbit brand-orbit-b" />
          </div>
          <div>
            <div className="brand-name">
              Singularity
            </div>

            <div className="brand-sub">
              Security Intelligence
            </div>
          </div>
        </div>


        <nav className="nav">
          {navGroups.map((group) => (
            <div
              className="nav-group"
              key={group.label}
            >
              <div className="nav-group-title">
                {group.label}
              </div>

              {group.items.map((item) => {
                const Icon = item.icon;

                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.to === "/"}
                    className={({ isActive }) =>
                      `nav-item ${isActive ? "active" : ""}`
                    }
                  >
                    <Icon size={17} />
                    <span>{item.label}</span>
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="version">
            Singularity v0.3.0
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="breadcrumb">
              Security Operations
              <ChevronRight size={14} />
              {title}
            </div>

            <h1>{title}</h1>
          </div>

          <div className="topbar-actions">


            <button className="avatar profile-button" type="button" onClick={() => navigate("/settings")} title="Account settings">
              {(user?.full_name || "Account")
                .split(/\s+/)
                .map((part) => part[0])
                .join("")
                .slice(0, 2)
                .toUpperCase()}
            </button>
          </div>
        </header>

        <div className="page-content">
          <Routes>
            <Route
              path="/CommandCenter"
              element={<CommandCenterPage />}
            />

            <Route path="/assets" element={<AssetsPage />} />

            <Route

              path="/vulnerabilities"
              element={<VulnerabilitiesPage />}
            />

            <Route
              path="/prioritization"
              element={<PrioritizationPage />}
            />

            {/* IMPORTANT:
                This route must come BEFORE :id */}
            <Route
              path="/prioritization/comparison"
              element={
                <PrioritizationComparisonPage />
              }
            />

            <Route
              path="/prioritization/:id"
              element={
                <VulnerabilityDetailPage />
              }
            />

            <Route
              path="/attack-paths"
              element={<AttackPathsPage />}
            />

            <Route
              path="/attack-paths/:id"
              element={<AttackPathDetailPage />}
            />

            <Route
              path="/remediation"
              element={<RemediationPage />}
            />

            <Route
              path="/threat-intel"
              element={
                <ThreatIntelligencePage />
              }
            />

            <Route
              path="/import"
              element={<EnvironmentImportPage />}
            />            <Route
              path="/investment"
              element={<InvestmentOptimizerPage />}
            />

            <Route
              path="/settings"
              element={<SettingsPage />}
            />
          </Routes>
        </div>
      </main>
    </div>
  );
}

function Dashboard() {
  const risk = useQuery({
    queryKey: ["risk-summary", getStoredUser()?.id],
    queryFn: api.riskSummary,
    refetchInterval: 30000,
  });

  const paths = useQuery({
    queryKey: ["attack-paths"],
    queryFn: api.attackPaths,
    refetchInterval: 30000,
  });

  const priorities = useQuery({
    queryKey: ["priorities", getStoredUser()?.id],
    queryFn: api.priorities,
    refetchInterval: 30000,
  });

  const assets = useQuery({
    queryKey: ["assets"],
    queryFn: api.assets,
    refetchInterval: 30000,
  });

  if (
    risk.isLoading ||
    paths.isLoading ||
    priorities.isLoading ||
    assets.isLoading
  ) {
    return (
      <LoadingState
        label="Loading security posture..."
      />
    );
  }

  if (
    risk.error ||
    paths.error ||
    priorities.error ||
    assets.error
  ) {
    return (
      <ErrorState
        message="Singularity could not reach the security API."
      />
    );
  }

  const riskData =
    risk.data as RiskSummary;

  const pathData =
    paths.data as AttackPathsResponse;

  const priorityData =
    priorities.data as PrioritiesResponse;

  const assetData =
    assets.data as Asset[];

  const criticalAssets =
    assetData.filter(
      (asset) =>
        asset.criticality ===
        "CRITICAL",
    ).length;

  const exposedAssets =
    assetData.filter(
      (asset) =>
        asset.internet_exposed,
    ).length;

  const chartData = [
    {
      name: "Critical",
      value: riskData.critical,
    },
    {
      name: "High",
      value: riskData.high,
    },
    {
      name: "Medium",
      value: riskData.medium,
    },
    {
      name: "Low",
      value: riskData.low,
    },
  ];

  const topPriorities =
    priorityData.results.slice(0, 4);

  const topPriority = topPriorities[0];

  const criticalPathCount =
    pathData.paths.filter(
      (path) =>
        path.target_criticality ===
        "CRITICAL",
    ).length;

  return (
    <div className="page-stack">
      <section className="hero-panel">
        <div>
          <div className="eyebrow">
            <Zap size={14} />
            SECURITY OPERATIONS
          </div>

          <h2>
            See how attackers could reach
            your critical systems.
          </h2>

          <p>
            Singularity correlates assets,
            vulnerabilities and network
            relationships to surface the
            attack paths that matter most.
          </p>
        </div>

        <div className="hero-score">
          <div className="score-label">
            Overall risk
          </div>

          <div className="score-value">
            {Math.round(
              riskData.overall_risk_score,
            )}
          </div>

          <div className="score-state">
            <span className="risk-dot" />

            {riskData.overall_risk_score >= 85
              ? "Critical exposure"
              : "Elevated exposure"}
          </div>
        </div>
      </section>

      <TopSecurityAction item={topPriorities[0]} />

      <section className="decision-snapshot">
        <div className="decision-snapshot-header">
          <div>
            <div className="eyebrow">
              <Sparkles size={14} />
              SECURITY DECISION SNAPSHOT
            </div>

            <h3>
              What should the team do next?
            </h3>

            <p>
              Singularity combines contextual risk,
              attack paths, and asset exposure into
              an actionable security decision.
            </p>
          </div>

          <Link
            to="/investment"
            className="decision-optimizer-link"
          >
            Open Investment Optimizer
            <ArrowUpRight size={15} />
          </Link>
        </div>

        <div className="decision-snapshot-grid">
          <div className="decision-stat">
            <span>Organizational risk</span>

            <strong>
              {Math.round(
                riskData.overall_risk_score,
              )}
              <small>/100</small>
            </strong>

            <p>
              {riskData.overall_risk_score >= 85
                ? "Immediate attention recommended"
                : "Elevated security exposure"}
            </p>
          </div>

          <div className="decision-stat">
            <span>Active attack paths</span>

            <strong>
              {pathData.path_count}
            </strong>

            <p>
              {criticalPathCount} reach critical
              targets
            </p>
          </div>

          <div className="decision-stat">
            <span>Internet exposure</span>

            <strong>
              {exposedAssets}
            </strong>

            <p>
              externally reachable assets
            </p>
          </div>

          <div className="decision-stat decision-stat-action">
            <span>Highest-priority action</span>

            {topPriority ? (
              <>
                <strong className="decision-action-title">
                  {topPriority.cve_id}
                </strong>

                <p>
                  Patch {topPriority.asset_name}
                  Highest-priority remediation action
                  risk {Math.round(
                    topPriority.risk_score,
                  )}
                  /100
                </p>

                <div className="decision-action-meta">
                  <span>
                    {
                      topPriority.attack_path_count
                    }{" "}
                    paths
                  </span>

                  <span>
                    {
                      topPriority
                        .critical_targets_reached
                    }{" "}
                    critical targets
                  </span>
                </div>
              </>
            ) : (
              <p>
                No remediation priority available.
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="metric-grid">
        <MetricCard
          icon={<Server size={18} />}
          label="Assets"
          value={assetData.length}
          detail={`${exposedAssets} internet exposed`}
        />

        <MetricCard
          icon={<ShieldAlert size={18} />}
          label="Vulnerabilities"
          value={
            riskData.total_vulnerabilities
          }
          detail={`${riskData.critical} critical`}
        />

        <MetricCard
          icon={<GitBranch size={18} />}
          label="Attack Paths"
          value={pathData.path_count}
          detail={`${pathData.choke_points.length} choke points`}
        />

        <MetricCard
          icon={<Database size={18} />}
          label="Critical Assets"
          value={criticalAssets}
          detail="High-value targets"
        />
      </section>

      <section className="two-column">
        <Panel
          title="Attack path overview"
          subtitle="Highest-risk paths to critical assets"
          action="Explore paths"
        >
          <div className="path-list">
            {pathData.paths.length === 0 ? (
              <EmptyState
                icon={<GitBranch size={20} />}
                title="No active attack paths"
                message="No modeled path currently reaches a critical target."
              />
            ) : (
              pathData.paths
                .slice(0, 4)
                .map((path, index) => (
                <Link
                  to={`/attack-paths/${index + 1}`}
                  className="path-row path-row-link"
                  key={`${path.source_asset_id}-${path.target_asset_id}-${index}`}
                >
                  <div className="path-index">
                    {String(index + 1).padStart(
                      2,
                      "0",
                    )}
                  </div>

                  <div className="path-main">
                    <div className="path-chain">
                      {path.asset_names.map(
                        (name, i) => (
                          <span
                            key={`${name}-${i}`}
                          >
                            {name}

                            {i <
                              path.asset_names
                                .length -
                                1 && (
                              <ChevronRight
                                size={13}
                              />
                            )}
                          </span>
                        ),
                      )}
                    </div>

                    <div className="path-meta">
                      <span>
                        {
                          path
                            .vulnerabilities
                            .length
                        }{" "}
                        vulnerability signals
                      </span>

                      <span>
                        {path.path_length} hops
                      </span>
                    </div>
                  </div>

                  <RiskPill
                    score={path.risk_score}
                  />
                </Link>
                ))
            )}
          </div>
        </Panel>

        <Panel
          title="Vulnerability distribution"
          subtitle="Current security findings"
        >
          <div className="chart-box">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis
                  dataKey="name"
                  stroke="#64748b"
                  tickLine={false}
                  axisLine={false}
                  fontSize={11}
                />
                <YAxis
                  stroke="#64748b"
                  tickLine={false}
                  axisLine={false}
                  fontSize={11}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#0b1220",
                    border: "1px solid rgba(96,165,250,.3)",
                    borderRadius: 12,
                    color: "#f8fafc",
                  }}
                  labelStyle={{ color: "#f8fafc", fontWeight: 700 }}
                  cursor={{ fill: "rgba(96,165,250,.06)" }}
                />
                <Bar
                  dataKey="value"
                  radius={[7, 7, 0, 0]}
                  fill="#60a5fa"
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel
          title="Top remediation priorities"
          subtitle="Highest-risk issues to address first"
          action="View all"
        >
          <div className="priority-list">
            {topPriorities.length === 0 ? (
              <EmptyState
                icon={<ShieldCheck size={20} />}
                title="No urgent remediation"
                message="Singularity found no prioritized remediation actions for the current environment."
              />
            ) : (
              topPriorities.map((item) => (
                <PriorityRow
                  key={`${item.vulnerability_id}-${item.asset_id}`}
                  item={item}
                />
              ))
            )}
          </div>
        </Panel>

        <Panel
          title="Why this matters"
          subtitle="Explainable security intelligence"
        >
          <div className="explain-card">
            <div className="explain-icon">
              <Crosshair size={20} />
            </div>

            <div>
              <div className="explain-title">
                Fixing the right weakness
                can break multiple attack
                paths.
              </div>

              <p>
                Singularity considers
                environment context rather
                than treating every high CVSS
                finding as equally urgent.
              </p>
            </div>
          </div>

          <div className="insight-list">
            <Insight
              label="Internet exposure"
              value={`${exposedAssets} assets`}
              icon={
                <Globe size={15} />
              }
            />

            <Insight
              label="Critical attack paths"
              value={`${
                pathData.paths.filter(
                  (p) =>
                    p.target_criticality ===
                    "CRITICAL",
                ).length
              } detected`}
              icon={
                <GitBranch size={15} />
              }
            />

            <Insight
              label="Average risk"
              value={`${Math.round(
                riskData.average_risk_score,
              )}/100`}
              icon={
                <Gauge size={15} />
              }
            />
          </div>
        </Panel>
      </section>
    </div>
  );
}

function AssetsPage() {
  const query = useQuery({
    queryKey: ["assets"],
    queryFn: api.assets,
  });

  if (query.isLoading) {
    return (
      <LoadingState label="Loading assets..." />
    );
  }

  if (query.error) {
    return (
      <ErrorState message="Unable to load assets." />
    );
  }

  const assets = query.data ?? [];

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="ATTACK SURFACE"
        title="Asset inventory"
        description="Every reachable system becomes part of the Singularity security graph."
      />

      <section className="panel">
        <div className="table-toolbar">
          <div className="toolbar-title">
            <span>{assets.length}</span>{" "}
            assets discovered
          </div>

          <AddAssetModal />
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>IP address</th>
                <th>Criticality</th>
                <th>Exposure</th>
              </tr>
            </thead>

            <tbody>
              {assets.map(
                (asset) => (
                  <tr key={asset.id}>
                    <td>
                      <div className="table-primary">
                        <span className="asset-icon">
                          <Server size={15} />
                        </span>

                        <div>
                          <strong>
                            {asset.name}
                          </strong>

                          <span>
                            {asset.hostname}
                          </span>
                        </div>
                      </div>
                    </td>

                    <td>
                      {asset.asset_type.replaceAll(
                        "_",
                        " ",
                      )}
                    </td>

                    <td className="mono">
                      {asset.ip_address ?? "-"}
                    </td>

                    <td>
                      <SeverityBadge
                        level={
                          asset.criticality
                        }
                      />
                    </td>

                    <td>
                      {asset.internet_exposed ? (
                        <span className="exposure public">
                          <Globe size={13} />
                          Internet-facing
                        </span>
                      ) : (
                        <span className="exposure private">
                          <LockKeyhole
                            size={13}
                          />
                          Internal
                        </span>
                      )}
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function VulnerabilitiesPage() {
  const query = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: api.vulnerabilities,
  });

  if (query.isLoading) {
    return (
      <LoadingState
        label="Loading vulnerabilities..."
      />
    );
  }

  if (query.error) {
    return (
      <ErrorState
        message="Unable to load vulnerabilities."
      />
    );
  }

  const vulnerabilities =
    query.data ?? [];

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="VULNERABILITY INTELLIGENCE"
        title="Vulnerability inventory"
        description="Raw findings enriched with contextual security information."
      />

      <section className="panel">
        <div className="table-toolbar">
          <div className="toolbar-title">
            <span>
              {vulnerabilities.length}
            </span>{" "}
            findings
          </div>

        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Finding</th>
                <th>CVSS</th>
                <th>Severity</th>
                <th>Exploitability</th>
                <th>Threat</th>
              </tr>
            </thead>

            <tbody>
              {vulnerabilities.map(
                (item) => (
                  <tr key={item.id}>
                    <td>
                      <div className="table-primary">
                        <span className="severity-icon">
                          <ShieldAlert
                            size={15}
                          />
                        </span>

                        <div>
                          <strong className="mono">
                            {item.cve_id}
                          </strong>

                          <span>
                            {item.title}
                          </span>
                        </div>
                      </div>
                    </td>

                    <td>
                      <strong>
                        {item.cvss_score.toFixed(
                          1,
                        )}
                      </strong>
                    </td>

                    <td>
                      <SeverityBadge
                        level={item.severity}
                      />
                    </td>

                    <td className="mono">
                      {item.exploitability_score?.toFixed(1) ?? "-"}
                    </td>
                    <td>
                      {item.actively_exploited ? (
                        <span className="threat-tag danger">
                          <AlertTriangle
                            size={12}
                          />
                          Active exploitation
                        </span>
                      ) : item.known_exploit ? (
                        <span className="threat-tag warning">
                          <Wifi size={12} />
                          Known exploit
                        </span>
                      ) : (
                        <span className="muted">
                          No known active threat
                        </span>
                      )}
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function PrioritizationPage() {
  const query = useQuery({
    queryKey: ["priorities", getStoredUser()?.id],
    queryFn: api.priorities,
  });

  if (query.isLoading) {
    return (
      <LoadingState
        label="Calculating contextual risk..."
      />
    );
  }

  if (query.error) {
    return (
      <ErrorState
        message="Unable to calculate priorities."
      />
    );
  }

  const results = query.data?.results ?? [];
  const topPriority = results[0];

  return (
    <div className="page-stack prioritization-page">
      <PageIntro
        eyebrow="RISK INTELLIGENCE"
        title="What should we fix first?"
        description="Singularity ranks vulnerabilities using environment context, not CVSS alone."
      />

      <section className="prioritization-hero">
        <div className="prioritization-hero-copy">
          <div className="prioritization-kicker">
            CONTEXTUAL PRIORITIZATION
          </div>

          <h2>
            Fix the weakness that creates the greatest exposure.
          </h2>

          <p>
            Singularity weighs vulnerability severity against the environment around it, so remediation starts with the weaknesses that matter most.
          </p>

          <Link
            to="/prioritization/comparison"
            className="prioritization-compare"
          >
            <BarChart3 size={16} />
            Compare with CVSS
            <ArrowUpRight size={14} />
          </Link>
        </div>

        <div className="prioritization-hero-focus">
          <span>HIGHEST PRIORITY</span>
          {topPriority ? (
            <>
              <strong>{topPriority.cve_id}</strong>
              <div className="prioritization-focus-asset">
                {topPriority.asset_name}
              </div>
              <div className="prioritization-focus-score">
                <b>{Math.round(topPriority.risk_score)}</b>
                <small>/100 contextual risk</small>
              </div>
            </>
          ) : (
            <div className="prioritization-empty-focus">
              No remediation priority available.
            </div>
          )}
        </div>
      </section>

      <section className="prioritization-snapshot">
        <div className="prioritization-snapshot-card">
          <span>PRIORITIES</span>
          <strong>{results.length}</strong>
          <p>ranked remediation findings</p>
        </div>

        <div className="prioritization-snapshot-card">
          <span>TOP RISK</span>
          <strong>{topPriority ? Math.round(topPriority.risk_score) : "-"}</strong>
          <p>contextual risk score</p>
        </div>

        <div className="prioritization-snapshot-card">
          <span>ATTACK PATHS</span>
          <strong>{topPriority ? topPriority.attack_path_count : "-"}</strong>
          <p>connected to the top priority</p>
        </div>

        <div className="prioritization-snapshot-card">
          <span>CRITICAL TARGETS</span>
          <strong>{topPriority ? topPriority.critical_targets_reached : "-"}</strong>
          <p>reached by the top priority</p>
        </div>
      </section>

      <section className="panel prioritization-list-panel">
        <div className="section-banner">
          <div>
            <div className="banner-label">
              REMEDIATION ORDER
            </div>

            <div className="banner-title">
              Start at the top. Work down by contextual risk.
            </div>
          </div>
        </div>

        <div className="priority-table">
          {results.map(
            (item) => (
              <PriorityRowLarge
                key={`${item.vulnerability_id}-${item.asset_id}`}
                item={item}
              />
            ),
          )}
        </div>
      </section>
    </div>
  );
}

function AttackPathsPage() {
  const query = useQuery({
    queryKey: ["graph-page"],
    queryFn: api.graph,
  });

  const paths = useQuery({
    queryKey: ["attack-paths-page"],
    queryFn: api.attackPaths,
  });

  if (
    query.isLoading ||
    paths.isLoading
  ) {
    return (
      <LoadingState
        label="Building attack graph..."
      />
    );
  }

  if (
    query.error ||
    paths.error
  ) {
    return (
      <ErrorState
        message="Unable to build attack graph."
      />
    );
  }

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="ATTACK PATH INTELLIGENCE"
        title="How could an attacker reach critical assets?"
        description="Interactive attack graph generated from the current enterprise topology."
      />

      <section className="attack-investment-bridge">
        <div>
          <div className="eyebrow">
            <Sparkles size={14} />
            FROM EXPOSURE TO DECISION
          </div>

          <h3>
            Turn attack-path intelligence into
            an investment plan.
          </h3>

          <p>
            Use Singularity's optimizer to compare
            remediation, segmentation, and exposure
            reduction against budget, engineering,
            and time constraints.
          </p>
        </div>

        <Link
          to="/investment"
          className="attack-investment-link"
        >
          Model investment response
          <ArrowUpRight size={15} />
        </Link>
      </section>

      <section className="graph-panel">
        <AttackGraph
          data={query.data!}
        />
      </section>
      <section className="attack-path-guide">
        <div className="attack-path-guide-title">How to read an attack path</div>
        <p className="attack-path-guide-intro">Each connection represents a possible movement route between systems. Follow the route from an exposed asset toward a critical asset to see how an attacker could progress through the environment.</p>
        <div className="attack-path-guide-grid">
          <div className="attack-path-guide-card"><strong>1. Start with exposure</strong><span>Internet-facing or otherwise exposed systems can provide an attacker entry point.</span></div>
          <div className="attack-path-guide-card"><strong>2. Follow the connections</strong><span>Each line represents a relationship or reachable route between two assets.</span></div>
          <div className="attack-path-guide-card"><strong>3. Look for critical targets</strong><span>Red-bordered assets are critical targets such as important databases or identity systems.</span></div>
          <div className="attack-path-guide-card"><strong>4. Focus on risky routes</strong><span>Higher-risk connections deserve more attention because compromising them can make movement toward critical systems easier.</span></div>
        </div>
      </section>

      <section className="two-column">
        <Panel
          title="Detected paths"
          subtitle={`${paths.data?.path_count ?? 0} possible paths to critical assets`}
        >
          <div className="path-list">
            {(
              paths.data?.paths ?? []
            ).map(
              (path, index) => (
                <Link
                  to={`/attack-paths/${index + 1}`}
                  className="path-row path-row-link"
                  key={`${path.source_asset_id}-${path.target_asset_id}-${index}`}
                >
                  <div className="path-index">
                    {String(
                      index + 1,
                    ).padStart(
                      2,
                      "0",
                    )}
                  </div>

                  <div className="path-main">
                    <div className="path-chain">
                      {path.asset_names.map(
                        (
                          name,
                          i,
                        ) => (
                          <span
                            key={`${name}-${i}`}
                          >
                            {name}

                            {i <
                              path
                                .asset_names
                                .length -
                                1 && (
                              <ChevronRight
                                size={
                                  13
                                }
                              />
                            )}
                          </span>
                        ),
                      )}
                    </div>

                    <div className="path-meta">
                      {
                        path
                          .vulnerabilities
                          .length
                      }{" "}
                      {
                        path.path_length
                      }{" "}
                      hops
                    </div>
                  </div>

                  <RiskPill
                    score={
                      path.risk_score
                    }
                  />
                </Link>
              ),
            )}
          </div>
        </Panel>

        <Panel
          title="Choke points"
          subtitle="Assets that sit across multiple attack routes"
        >
          <div className="choke-list">
            {(
              paths.data
                ?.choke_points ??
              []
            ).map(
              (item) => (
                <div
                  className="choke-row"
                  key={item.asset_id}
                >
                  <div className="choke-icon">
                    <CircleDot
                      size={17}
                    />
                  </div>

                  <div>
                    <strong>
                      {item.asset_name}
                    </strong>

                    <span>
                      {
                        item
                          .vulnerabilities
                          .length
                      }{" "}
                      vulnerabilities
                    </span>
                  </div>
                </div>
              ),
            )}
          </div>
        </Panel>
      </section>
    </div>
  );
}

function NetworkPage() {
  const query = useQuery({
    queryKey: ["network-graph"],
    queryFn: api.graph,
  });

  if (query.isLoading) {
    return (
      <LoadingState
        label="Loading network map..."
      />
    );
  }

  if (query.error) {
    return (
      <ErrorState
        message="Unable to load network topology."
      />
    );
  }

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="ATTACK SURFACE"
        title="Network topology"
        description="Current relationships between exposed systems and internal assets."
      />

      <section className="graph-panel">
        <AttackGraph
          data={query.data!}
        />
      </section>
    </div>
  );
}

function RemediationPage() {
  const query = useQuery({
    queryKey: [
      "priorities-remediation",
    ],
    queryFn: api.priorities,
  });

  if (query.isLoading) {
    return (
      <LoadingState
        label="Loading remediation intelligence..."
      />
    );
  }

  if (query.error) {
    return (
      <ErrorState
        message="Unable to load remediation data."
      />
    );
  }

  const results =
    query.data?.results ?? [];

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="SECURITY OPERATIONS"
        title="Remediation queue"
        description="A prioritized action list generated from current environmental risk."
      />

      <div className="remediation-grid">
        {results.map(
          (item) => (
            <div
              className="remediation-card"
              key={
                item.vulnerability_id
              }
            >
              <div className="remediation-top">
                <SeverityBadge
                  level={item.priority}
                />

                <div className="remediation-score">
                  {Math.round(
                    item.risk_score,
                  )}
                </div>
              </div>

              <div className="mono remediation-cve">
                {item.cve_id}
              </div>

              <h3>{item.title}</h3>

              <div className="remediation-meta">
                <span>
                  <Server
                    size={13}
                  />
                  {item.asset_name}
                </span>

                <span>
                  <GitBranch
                    size={13}
                  />
                  {
                    item.attack_path_count
                  }{" "}
                  paths
                </span>
              </div>

              <div className="reason-pills">
                {item.reasons
                  .slice(
                    0,
                    3,
                  )
                  .map(
                    (
                      reason,
                    ) => (
                      <span
                        key={
                          reason
                        }
                      >
                        {reason}
                      </span>
                    ),
                  )}
              </div>

              <Link
                to={`/prioritization/${item.vulnerability_id}?asset_id=${item.asset_id}`}
                className="secondary-button"
              >
                Review remediation
                <ArrowUpRight
                  size={14}
                />
              </Link>
            </div>
          ),
        )}
      </div>
    </div>
  );
}

function SettingsPage() {
  const user = getStoredUser();
  const navigate = useNavigate();

  const handleSignOut = () => {
    clearSession();
    navigate("/", { replace: true });
  };

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="PLATFORM"
        title="Settings"
        description="Singularity environment and security configuration."
      />

      <section className="panel settings-panel">
        <div className="settings-account">
          <div className="settings-account-avatar">
            {(user?.full_name || "AR")
              .split(" ")
              .map((part) => part[0])
              .join("")
              .slice(0, 2)
              .toUpperCase()}
          </div>

          <div className="settings-account-info">
            <span className="settings-account-label">SIGNED IN AS</span>
            <strong>{user?.full_name || "Singularity User"}</strong>
            <span>{user?.email || "No account email available"}</span>
          </div>

          <button
            type="button"
            className="settings-signout"
            onClick={handleSignOut}
          >
            Sign out
          </button>
        </div>

        <SettingRow
          title="API connectivity"
          description="FastAPI security intelligence service"
        />

        <SettingRow
          title="Database"
          description="PostgreSQL asset and vulnerability store"
        />

        <SettingRow
          title="Attack graph"
          description="NetworkX relationship and path analysis"
        />
      </section>
    </div>
  );
}

function AttackGraph({
  data,
}: {
  data: NetworkGraphResponse;
}) {
  const nodeSpacingX = 260;
  const nodeSpacingY = 130;

  const nodes: Node[] =
    data.nodes.map(
      (node, index) => {
        const critical =
          node.criticality ===
          "CRITICAL";

        const exposed =
          node.internet_exposed;

        return {
          id: String(node.id),

          position: {
            x:
              (index % 3) *
              nodeSpacingX,
            y:
              Math.floor(
                index / 3,
              ) *
              nodeSpacingY,
          },

          data: {
            label: (
              <div className="flow-node">
                <div className="flow-node-icon">
                  {exposed ? (
                    <Globe size={15} />
                  ) : (
                    <Server size={15} />
                  )}
                </div>

                <div>
                  <strong>
                    {node.name}
                  </strong>

                  <span>
                    {critical
                      ? "Critical target"
                      : exposed
                        ? "Internet exposed"
                        : node.asset_type.replaceAll(
                            "_",
                            " ",
                          )}
                  </span>
                </div>
              </div>
            ),
          },

          className:
            critical
              ? "flow-node-wrapper critical"
              : exposed
                ? "flow-node-wrapper exposed"
                : "flow-node-wrapper",
        };
      },
    );

  const edges: Edge[] =
    data.edges.map(
      (edge, index) => ({
        id: `e-${index}-${edge.source}-${edge.target}`,
        source:
          String(edge.source),
        target:
          String(edge.target),

        animated:
          edge.trust_level !==
          "LOW",

        style: {
          stroke:
            edge.trust_level ===
            "HIGH"
              ? "#fb7185"
              : edge.trust_level ===
                  "MEDIUM"
                ? "#60a5fa"
                : "#64748b",

          strokeWidth: 1.8,
        },
      }),
    );

  return (
    <div className="flow-container">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={0.55}
        maxZoom={1.35}
        attributionPosition="bottom-left"
      >
        <MiniMap
          pannable
          zoomable
          style={{
            background:
              "#09101d",
            border:
              "1px solid rgba(148,163,184,.15)",
          }}
        />

        <Controls />

        <Background
          color="#1f2937"
          gap={24}
          size={1}
        />
      </ReactFlow>
      <div className="flow-explanation">
        <div className="flow-explanation-title">How to read this map</div>
        <div className="flow-explanation-grid">
          <div className="flow-explanation-item">
            <span className="flow-dot high"></span>
            <div><strong>High-risk path</strong><small>A connection with a weaker trust boundary. If compromised, an attacker may use it to move closer to a critical system.</small></div>
          </div>
          <div className="flow-explanation-item">
            <span className="flow-dot medium"></span>
            <div><strong>Medium-risk path</strong><small>A connection with moderate trust. It represents a possible movement route that still needs attention.</small></div>
          </div>
          <div className="flow-explanation-item">
            <span className="flow-dot low"></span>
            <div><strong>Low-risk path</strong><small>A more trusted connection. It is still part of the environment but represents less immediate path risk.</small></div>
          </div>
          <div className="flow-explanation-item">
            <span className="flow-dot direction"></span>
            <div><strong>How to read the path</strong><small>Follow the connected assets from the exposed system toward the critical target to understand how an attacker could move through the environment.</small></div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  icon,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  detail: string;
}) {
  return (
    <div className="metric-card">
      <div className="metric-icon">
        {icon}
      </div>

      <div className="metric-label">
        {label}
      </div>

      <div className="metric-value">
        {value}
      </div>

      <div className="metric-detail">
        {detail}
      </div>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  action,
  children,
}: {
  title: string;
  subtitle: string;
  action?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="panel-title">
            {title}
          </div>

          <div className="panel-subtitle">
            {subtitle}
          </div>
        </div>

        {action && (
          action === "Explore paths" ? (
            <Link
              to="/attack-paths"
              className="panel-action"
            >
              {action}
            </Link>
          ) : action === "View all" ? (
            <Link
              to="/remediation"
              className="panel-action"
            >
              {action}
            </Link>
          ) : (
            <button
              type="button"
              className="panel-action"
            >
              {action}
            </button>
          )
        )}
      </div>

      {children}
    </section>
  );
}

function PriorityRow({
  item,
}: {
  item: PriorityResult;
}) {
  return (
    <Link
      to={`/prioritization/${item.vulnerability_id}?asset_id=${item.asset_id}`}
      className="priority-row priority-row-link"
    >
      <div className="priority-rank">
        #{item.rank}
      </div>

      <div className="priority-main">
        <div className="priority-title">
          <span className="mono">
            {item.cve_id}
          </span>

          <SeverityBadge
            level={item.priority}
          />
        </div>

        <div className="priority-desc">
          {item.asset_name} ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€š. {item.attack_path_count} attack paths
        </div>
      </div>

      <div className="priority-score">
        <strong>
          {Math.round(item.risk_score)}
        </strong>

        <span>/100</span>
      </div>
    </Link>
  );
}

function PriorityRowLarge({
  item,
}: {
  item: PriorityResult;
}) {
  return (
    <Link
      to={`/prioritization/${item.vulnerability_id}?asset_id=${item.asset_id}`}
      className="priority-large priority-large-link"
    >
      <div className="priority-large-rank">
        #{item.rank}
      </div>

      <div className="priority-large-main">
        <div className="priority-large-title">
          <div>
            <span className="mono">
              {item.cve_id}
            </span>

            <h3>
              {item.title}
            </h3>
          </div>

          <SeverityBadge
            level={item.priority}
          />
        </div>

        <div className="priority-large-meta">
          <span>
            <Server size={13} />
            {item.asset_name}
          </span>

          <span>
            <GitBranch size={13} />
            {item.attack_path_count}{" "}
            attack paths
          </span>

          <span>
            <Database size={13} />
            {
              item.critical_targets_reached
            }{" "}
            critical targets
          </span>

          {item.choke_point && (
            <span>
              <CircleDot
                size={13}
              />
              Choke point
            </span>
          )}
        </div>

        <div className="reason-pills">
          {item.reasons
            .slice(0, 4)
            .map(
              (reason) => (
                <span
                  key={
                    reason
                  }
                >
                  {reason}
                </span>
              ),
            )}
        </div>
      </div>

      <div className="priority-large-score">
        <div className="large-score">
          {Math.round(
            item.risk_score,
          )}
        </div>

        <div>
          contextual risk
        </div>
      </div>
    </Link>
  );
}

function RiskPill({
  score,
}: {
  score: number;
}) {
  const tone =
    score >= 85
      ? "critical"
      : score >= 70
        ? "high"
        : score >= 45
          ? "medium"
          : "low";

  return (
    <div
      className={`risk-pill ${tone}`}
    >
      <span>
        {Math.round(score)}
      </span>

      <small>risk</small>
    </div>
  );
}

function SeverityBadge({
  level,
}: {
  level: string;
}) {
  return (
    <span
      className={`severity-badge ${level.toLowerCase()}`}
    >
      {level}
    </span>
  );
}

function Insight({
  label,
  value,
  icon,
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="insight-row">
      <div className="insight-left">
        {icon}
        <span>
          {label}
        </span>
      </div>

      <strong>
        {value}
      </strong>
    </div>
  );
}

function PageIntro({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <section className="page-intro">
      <div className="eyebrow">
        {eyebrow}
      </div>

      <h2>{title}</h2>

      <p>{description}</p>
    </section>
  );
}

function SettingRow({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>
          {title}
        </strong>

        <span>
          {description}
        </span>
      </div>

      <div className="setting-row-mark" aria-hidden="true">
        <span />
      </div>
    </div>
  );
}

function EmptyState({
  icon,
  title,
  message,
}: {
  icon: React.ReactNode;
  title: string;
  message: string;
}) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon">
        {icon}
      </div>

      <strong>{title}</strong>

      <span>{message}</span>
    </div>
  );
}

function LoadingState({
  label,
}: {
  label: string;
}) {
  return (
    <div className="state-card state-card-polished">
      <div className="state-icon-shell">
        <div className="loader" />
      </div>

      <strong>{label}</strong>

      <span>
        Correlating assets, vulnerabilities,
        threat intelligence, and attack paths.
      </span>

      <div className="state-progress">
        <span />
      </div>
    </div>
  );
}

function ErrorState({
  message,
}: {
  message: string;
}) {
  return (
    <div className="state-card error-state state-card-polished">
      <div className="state-icon-shell state-icon-error">
        <AlertTriangle size={22} />
      </div>

      <strong>{message}</strong>

      <span>
        Security intelligence is temporarily
        unavailable. Check the platform services
        and retry.
      </span>

      <button
        type="button"
        className="state-retry-button"
        onClick={() => window.location.reload()}
      >
        Retry connection
      </button>
    </div>
  );
}

export default App;


































