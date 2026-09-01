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
} from "react-router-dom";

import { useQuery } from "@tanstack/react-query";

import VulnerabilityDetailPage from "./VulnerabilityDetailPage";
import PrioritizationComparisonPage from "./PrioritizationComparisonPage";
import AttackPathDetailPage from "./AttackPathDetailPage";
import ThreatIntelligencePage from "./ThreatIntelligencePage";
import TopSecurityAction from "./TopSecurityAction";
import EnvironmentImportPage from "./EnvironmentImportPage";
import InvestmentOptimizerPage from "./InvestmentOptimizerPage";

import {
  api,
  type Asset,
  type AttackPathsResponse,
  type NetworkGraphResponse,
  type PrioritiesResponse,
  type PriorityResult,
  type RiskSummary,
} from "./lib/api";

import "./App.css";

function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}

const navGroups = [
  {
    label: "Overview",
    items: [
      {
        to: "/",
        label: "Command Center",
        icon: LayoutDashboard,
      },
    ],
  },
  {
    label: "Attack Surface",
    items: [
      {
        to: "/assets",
        label: "Assets",
        icon: Server,
      },
      {
        to: "/network",
        label: "Network Map",
        icon: Network,
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
        to: "/remediation",
        label: "Remediation",
        icon: Crosshair,
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
      },      {
        to: "/investment",
        label: "Investment Optimizer",
        icon: Sparkles,
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

  const title = (() => {
    if (location.pathname === "/") {
      return "Command Center";
    }

    if (location.pathname === "/assets") {
      return "Attack Surface";
    }

    if (location.pathname === "/network") {
      return "Network Map";
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
          <div className="brand-mark">
            <ShieldCheck
              size={20}
              strokeWidth={2.2}
            />
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

        <div className="sidebar-status">
          <span className="status-dot" />
          <span>Environment secure</span>
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
          <div className="footer-chip">
            <LockKeyhole size={15} />
            <span>Protected workspace</span>
          </div>

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
            <div className="live-status">
              <span className="status-dot" />
              Systems operational
            </div>

            <button
              className="icon-button"
              title="Search"
            >
              <Search size={18} />
            </button>

            <div className="avatar">
              AR
            </div>
          </div>
        </header>

        <div className="page-content">
          <Routes>
            <Route
              path="/"
              element={<Dashboard />}
            />

            <Route
              path="/assets"
              element={<AssetsPage />}
            />

            <Route
              path="/network"
              element={<NetworkPage />}
            />

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
            LIVE SECURITY POSTURE
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
                  {" · "}
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
            {pathData.paths
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
              ))}
          </div>
        </Panel>

        <Panel
          title="Vulnerability distribution"
          subtitle="Current security findings"
        >
          <div className="chart-box">
            <ResponsiveContainer
              width="100%"
              height="100%"
            >
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
                    background:
                      "#0b1220",
                    border:
                      "1px solid rgba(148,163,184,.16)",
                    borderRadius: 12,
                    color: "#fff",
                  }}
                />

                <Bar
                  dataKey="value"
                  radius={[
                    7,
                    7,
                    0,
                    0,
                  ]}
                  fill="#60a5fa"
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </section>

      <section className="two-column">
        <Panel
          title="Top remediation priorities"
          subtitle="Context-aware ranking"
          action="View all"
        >
          <div className="priority-list">
            {topPriorities.map(
              (item) => (
                <PriorityRow
                  key={`${item.vulnerability_id}-${item.asset_id}`}
                  item={item}
                />
              ),
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

          <button className="primary-button">
            <PackageSearch size={16} />
            Add asset
          </button>
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
                      {asset.ip_address ??
                        "—"}
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

          <div className="search-box">
            <Search size={15} />
            <input
              placeholder="Search CVE or finding..."
            />
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
                      {item.exploitability_score?.toFixed(
                        1,
                      ) ?? "—"}
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
    queryKey: ["priorities"],
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

  const results =
    query.data?.results ?? [];

  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="RISK INTELLIGENCE"
        title="What should we fix first?"
        description="Singularity ranks vulnerabilities using environment context, not CVSS alone."
      />

      <section className="panel">
        <div className="section-banner">
          <div>
            <div className="banner-label">
              CONTEXTUAL PRIORITIZATION
            </div>

            <div className="banner-title">
              The most severe CVE isn't always
              the most dangerous one.
            </div>
          </div>

          <Link
            to="/prioritization/comparison"
            className="banner-chip comparison-link"
          >
            <BarChart3 size={15} />
            Compare with CVSS
            <ArrowUpRight size={13} />
          </Link>
        </div>

        <div className="priority-table">
          {results.map(
            (item) => (
              <PriorityRowLarge
                key={
                  item.vulnerability_id
                }
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

      <section className="graph-panel">
        <AttackGraph
          data={query.data!}
        />
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
                      vulnerability signals ·{" "}
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
                      {item.path_count} attack paths ·{" "}
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
  return (
    <div className="page-stack">
      <PageIntro
        eyebrow="PLATFORM"
        title="Settings"
        description="Singularity environment and security configuration."
      />

      <section className="panel settings-panel">
        <SettingRow
          title="API connectivity"
          description="FastAPI security intelligence service"
          status="Operational"
        />

        <SettingRow
          title="Database"
          description="PostgreSQL asset and vulnerability store"
          status="Operational"
        />

        <SettingRow
          title="Attack graph"
          description="NetworkX relationship and path analysis"
          status="Operational"
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
        minZoom={0.45}
        maxZoom={1.5}
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
          <button className="panel-action">
            {action}
          </button>
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
          {item.asset_name} ·{" "}
          {item.attack_path_count}{" "}
          attack paths
        </div>
      </div>

      <div className="priority-score">
        <strong>
          {Math.round(
            item.risk_score,
          )}
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
  status,
}: {
  title: string;
  description: string;
  status: string;
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

      <div className="operational">
        <span className="status-dot" />
        {status}
      </div>
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


























