import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Database,
  Globe,
  GitBranch,
  Server,
  ShieldAlert,
  ShieldCheck,
  Target,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api } from "./lib/api";

export default function AttackPathDetailPage() {
  const { id } = useParams<{ id: string }>();

  const pathIndex = Number(id);

  const query = useQuery({
    queryKey: ["attack-path-detail", pathIndex],
    queryFn: api.attackPaths,
  });

  if (query.isLoading) {
    return (
      <div className="state-card">
        <div className="loader" />
        <strong>Analyzing attack path...</strong>
        <span>
          Loading the current attack graph intelligence.
        </span>
      </div>
    );
  }

  if (query.error || !query.data) {
    return (
      <div className="state-card error-state">
        <AlertTriangle size={24} />
        <strong>Unable to load attack path.</strong>
        <span>
          Verify that the AegisPath API is running on port 8000.
        </span>
      </div>
    );
  }

  const paths = query.data.paths;

  const path = paths[pathIndex - 1];

  if (!path) {
    return (
      <div className="state-card error-state">
        <AlertTriangle size={24} />
        <strong>Attack path not found.</strong>
        <span>
          The requested path does not exist in the current graph.
        </span>
      </div>
    );
  }

  const isCritical =
    path.target_criticality === "CRITICAL";

  return (
    <div className="page-stack attack-path-detail-page">
      <Link
        to="/attack-paths"
        className="back-link"
      >
        <ArrowLeft size={14} />
        Back to attack paths
      </Link>

      <section className="attack-path-header">
        <div>
          <div className="eyebrow">
            <GitBranch size={14} />
            ATTACK PATH INVESTIGATION
          </div>

          <div className="attack-path-id">
            PATH-{String(pathIndex).padStart(3, "0")}
          </div>

          <h2>
            {path.asset_names[0]} →{" "}
            {path.asset_names[path.asset_names.length - 1]}
          </h2>

          <p>
            AegisPath identified a possible route from the source
            asset to the target asset based on the current network
            relationships and vulnerability context.
          </p>
        </div>

        <div className="attack-path-risk">
          <span>PATH RISK</span>
          <strong>{Math.round(path.risk_score)}</strong>
          <small>/100</small>

          <div
            className={`attack-path-criticality ${
              isCritical ? "critical" : "elevated"
            }`}
          >
            {isCritical
              ? "Critical target"
              : "Elevated target"}
          </div>
        </div>
      </section>

      <section className="metric-grid">
        <PathMetric
          icon={<GitBranch size={18} />}
          label="Path length"
          value={path.path_length}
          detail="network hops"
        />

        <PathMetric
          icon={<ShieldAlert size={18} />}
          label="Vulnerabilities"
          value={path.vulnerabilities.length}
          detail="security signals"
        />

        <PathMetric
          icon={<Target size={18} />}
          label="Target"
          value={isCritical ? "Critical" : path.target_criticality}
          detail="asset criticality"
        />

        <PathMetric
          icon={<CircleDot size={18} />}
          label="Choke points"
          value={path.choke_points.length}
          detail="strategic positions"
        />
      </section>

      <section className="attack-path-card">
        <div className="attack-path-card-header">
          <div>
            <div className="panel-title">
              Attack progression
            </div>

            <div className="panel-subtitle">
              How the path moves through the environment
            </div>
          </div>

          <div className="path-status">
            <span className="status-dot" />
            Graph analysis
          </div>
        </div>

        <div className="attack-path-flow">
          {path.asset_names.map((name, index) => (
            <div
              className="attack-path-step-wrapper"
              key={`${name}-${index}`}
            >
              <div
                className={`attack-path-step ${
                  index === 0
                    ? "entry"
                    : index === path.asset_names.length - 1
                      ? "target"
                      : ""
                }`}
              >
                <div className="attack-step-icon">
                  <AssetIcon
                    name={name}
                    isEntry={index === 0}
                    isTarget={
                      index ===
                      path.asset_names.length - 1
                    }
                  />
                </div>

                <div>
                  <strong>{name}</strong>

                  <span>
                    {index === 0
                      ? "Entry point"
                      : index ===
                          path.asset_names.length - 1
                        ? "Target asset"
                        : "Lateral movement"}
                  </span>
                </div>
              </div>

              {index <
                path.asset_names.length - 1 && (
                <ChevronRight
                  className="attack-path-arrow"
                  size={18}
                />
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="two-column">
        <section className="attack-path-card">
          <div className="attack-path-card-header">
            <div>
              <div className="panel-title">
                Vulnerabilities involved
              </div>

              <div className="panel-subtitle">
                Findings that contribute to this route
              </div>
            </div>
          </div>

          {path.vulnerabilities.length > 0 ? (
            <div className="path-vulnerability-list">
              {path.vulnerabilities.map(
                (cve) => (
                  <div
                    className="path-vulnerability"
                    key={cve}
                  >
                    <div className="path-vulnerability-icon">
                      <ShieldAlert size={15} />
                    </div>

                    <div>
                      <strong className="mono">
                        {cve}
                      </strong>

                      <span>
                        Contributes to this attack route
                      </span>
                    </div>

                    <Link
                      to="/prioritization"
                      className="path-open-link"
                    >
                      Investigate
                      <ChevronRight size={13} />
                    </Link>
                  </div>
                ),
              )}
            </div>
          ) : (
            <div className="empty-path-state">
              <ShieldCheck size={18} />
              <span>
                No vulnerability associations were returned
                for this path.
              </span>
            </div>
          )}
        </section>

        <section className="attack-path-card">
          <div className="attack-path-card-header">
            <div>
              <div className="panel-title">
                Strategic choke points
              </div>

              <div className="panel-subtitle">
                Assets that can affect multiple routes
              </div>
            </div>
          </div>

          {path.choke_points.length > 0 ? (
            <div className="choke-detail-list">
              {path.choke_points.map(
                (assetId) => {
                  const assetName =
                    path.asset_names.find(
                      (name, index) =>
                        path.asset_ids[index] ===
                        assetId,
                    );

                  return (
                    <div
                      className="choke-detail"
                      key={assetId}
                    >
                      <CircleDot size={16} />

                      <div>
                        <strong>
                          {assetName ??
                            `Asset ${assetId}`}
                        </strong>

                        <span>
                          Choke point in current attack graph
                        </span>
                      </div>
                    </div>
                  );
                },
              )}
            </div>
          ) : (
            <div className="empty-path-state">
              <CheckCircle2 size={18} />
              <span>
                No choke points identified on this path.
              </span>
            </div>
          )}
        </section>
      </section>

      <section className="attack-path-action">
        <div>
          <div className="eyebrow">
            <ShieldCheck size={14} />
            SECURITY DECISION
          </div>

          <h2>
            Breaking this path reduces attacker reachability.
          </h2>

          <p>
            Prioritize vulnerabilities that sit on high-risk
            paths toward critical assets, especially when they
            also occupy strategic choke points.
          </p>
        </div>

        <Link
          to="/prioritization"
          className="primary-button"
        >
          Review remediation priorities
          <ChevronRight size={15} />
        </Link>
      </section>
    </div>
  );
}

function PathMetric({
  icon,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
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

function AssetIcon({
  name,
  isEntry,
  isTarget,
}: {
  name: string;
  isEntry: boolean;
  isTarget: boolean;
}) {
  const lower = name.toLowerCase();

  if (isEntry || lower.includes("internet")) {
    return <Globe size={17} />;
  }

  if (isTarget && lower.includes("database")) {
    return <Database size={17} />;
  }

  if (isTarget) {
    return <ShieldAlert size={17} />;
  }

  return <Server size={17} />;
}
