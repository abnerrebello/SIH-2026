import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  Globe,
  ShieldCheck,
  Sparkles,
  Target,
  Wifi,
} from "lucide-react";
import { Link } from "react-router-dom";

import { api } from "./lib/api";

export default function ThreatIntelligencePage() {
  const vulnerabilities = useQuery({
    queryKey: ["threat-vulnerabilities"],
    queryFn: api.vulnerabilities,
  });

  const priorities = useQuery({
    queryKey: ["threat-priorities"],
    queryFn: api.priorities,
  });

  if (vulnerabilities.isLoading || priorities.isLoading) {
    return (
      <div className="state-card">
        <div className="loader" />
        <strong>Building threat intelligence...</strong>
        <span>
          Correlating vulnerabilities with current security context.
        </span>
      </div>
    );
  }

  if (vulnerabilities.error || priorities.error) {
    return (
      <div className="state-card error-state">
        <AlertTriangle size={24} />
        <strong>Unable to load threat intelligence.</strong>
        <span>
          Verify that the Singularity API is running on port 8000.
        </span>
      </div>
    );
  }

  const vulns = vulnerabilities.data ?? [];
  const priorityData = priorities.data?.results ?? [];

  const activeThreats = vulns.filter(
    (item) => item.actively_exploited,
  );

  const knownExploits = vulns.filter(
    (item) => item.known_exploit,
  );

  const internetExposedThreats = priorityData.filter(
    (item) =>
      item.reasons.some((reason) =>
        reason.toLowerCase().includes("internet"),
      ),
  );

  const highestRisk = [...priorityData].sort(
    (a, b) => b.risk_score - a.risk_score,
  )[0];

  return (
    <div className="page-stack threat-page">
      <section className="page-intro">
        <div className="eyebrow">
          <Activity size={14} />
          THREAT INTELLIGENCE
        </div>

        <h2>Understand the threat behind the CVE.</h2>

        <p>
          Singularity correlates vulnerability severity, exploit signals,
          internet exposure and attack-path impact to turn raw findings
          into actionable threat intelligence.
        </p>
      </section>

      <section className="threat-hero">
        <div className="threat-hero-content">
          <div className="threat-live">
            <span className="status-dot" />
            Security signals active
          </div>

          <h2>
            Your highest-risk vulnerability is{" "}
            {highestRisk?.cve_id ?? "being calculated"}.
          </h2>

          <p>
            The current threat view combines vulnerability intelligence
            with the environment Singularity is protecting.
          </p>
        </div>

        <div className="threat-hero-score">
          <span>TOP CONTEXTUAL RISK</span>
          <strong>
            {highestRisk
              ? Math.round(highestRisk.risk_score)
              : 0}
          </strong>
          <small>/ 100</small>
        </div>
      </section>

      <section className="metric-grid">
        <ThreatMetric
          icon={<AlertTriangle size={18} />}
          label="Active exploitation"
          value={activeThreats.length}
          detail="currently flagged"
          tone="danger"
        />

        <ThreatMetric
          icon={<Wifi size={18} />}
          label="Known exploits"
          value={knownExploits.length}
          detail="exploit signal"
          tone="warning"
        />

        <ThreatMetric
          icon={<Globe size={18} />}
          label="Internet-facing risk"
          value={internetExposedThreats.length}
          detail="exposed findings"
          tone="blue"
        />

        <ThreatMetric
          icon={<Target size={18} />}
          label="Tracked findings"
          value={vulns.length}
          detail="vulnerabilities"
          tone="green"
        />
      </section>

      <section className="two-column">
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                Threat signals
              </div>

              <div className="panel-subtitle">
                Current evidence affecting vulnerability urgency
              </div>
            </div>

            <div className="banner-chip">
              <Activity size={13} />
              Live analysis
            </div>
          </div>

          <div className="threat-signal-list">
            <ThreatSignal
              title="Active exploitation"
              description="A vulnerability is associated with active exploitation signals."
              value={`${activeThreats.length} finding${
                activeThreats.length === 1 ? "" : "s"
              }`}
              tone="danger"
              active={activeThreats.length > 0}
            />

            <ThreatSignal
              title="Known exploit availability"
              description="Known exploitability can increase remediation urgency."
              value={`${knownExploits.length} finding${
                knownExploits.length === 1 ? "" : "s"
              }`}
              tone="warning"
              active={knownExploits.length > 0}
            />

            <ThreatSignal
              title="Internet exposure"
              description="External exposure gives attackers a more direct entry point."
              value={`${internetExposedThreats.length} finding${
                internetExposedThreats.length === 1 ? "" : "s"
              }`}
              tone="blue"
              active={internetExposedThreats.length > 0}
            />
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                Intelligence pipeline
              </div>

              <div className="panel-subtitle">
                External security-data sources
              </div>
            </div>
          </div>

          <div className="intel-pipeline">
            <PipelineItem
              name="NVD / CVE"
              description="Vulnerability metadata"
              state="Ready for ingestion"
            />

            <PipelineItem
              name="EPSS"
              description="Exploitation probability"
              state="Integration pending"
            />

            <PipelineItem
              name="MITRE ATT&CK"
              description="Adversary technique context"
              state="Integration pending"
            />
          </div>
        </section>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Highest-risk findings
            </div>

            <div className="panel-subtitle">
              Threat context combined with Singularity risk
            </div>
          </div>

          <Link
            to="/prioritization"
            className="panel-action threat-link"
          >
            Open prioritization
            <ArrowUpRight size={13} />
          </Link>
        </div>

        <div className="threat-findings">
          {priorityData.slice(0, 5).map((item) => {
            const related =
              vulns.find(
                (v) => v.id === item.vulnerability_id,
              );

            return (
              <Link
                key={item.vulnerability_id}
                to={`/prioritization/${item.vulnerability_id}`}
                className="threat-finding"
              >
                <div className="threat-finding-rank">
                  #{item.rank}
                </div>

                <div className="threat-finding-main">
                  <div className="threat-finding-title">
                    <span className="mono">
                      {item.cve_id}
                    </span>

                    <ThreatBadge
                      active={
                        related?.actively_exploited ??
                        false
                      }
                      known={
                        related?.known_exploit ??
                        false
                      }
                    />
                  </div>

                  <strong>{item.title}</strong>

                  <span>
                    {item.asset_name} ·{" "}
                    {item.attack_path_count} attack paths
                  </span>
                </div>

                <div className="threat-finding-score">
                  {Math.round(item.risk_score)}
                </div>

                <ChevronRight size={15} />
              </Link>
            );
          })}
        </div>
      </section>

      <section className="mitre-preview">
        <div className="mitre-icon">
          <ShieldCheck size={21} />
        </div>

        <div>
          <div className="eyebrow">
            <Sparkles size={13} />
            MITRE ATT&CK ENRICHMENT
          </div>

          <h2>
            Connect vulnerabilities to attacker behavior.
          </h2>

          <p>
            Once MITRE ATT&CK mappings are ingested, Singularity will
            show the techniques and tactics associated with exploitable
            vulnerabilities and connect them to observed attack paths.
          </p>
        </div>

        <div className="mitre-status">
          <CheckCircle2 size={15} />
          Architecture ready
        </div>
      </section>
    </div>
  );
}

function ThreatMetric({
  icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  detail: string;
  tone: string;
}) {
  return (
    <div className={`metric-card threat-metric ${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

function ThreatSignal({
  title,
  description,
  value,
  tone,
  active,
}: {
  title: string;
  description: string;
  value: string;
  tone: string;
  active: boolean;
}) {
  return (
    <div className={`threat-signal ${tone}`}>
      <div className="threat-signal-icon">
        {active ? (
          <AlertTriangle size={15} />
        ) : (
          <CheckCircle2 size={15} />
        )}
      </div>

      <div className="threat-signal-main">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>

      <div className="threat-signal-value">
        {value}
      </div>
    </div>
  );
}

function PipelineItem({
  name,
  description,
  state,
}: {
  name: string;
  description: string;
  state: string;
}) {
  const ready = state === "Ready for ingestion";

  return (
    <div className="pipeline-item">
      <div className="pipeline-status">
        <span className={ready ? "ready" : "pending"} />
      </div>

      <div className="pipeline-main">
        <strong>{name}</strong>
        <span>{description}</span>
      </div>

      <div className={`pipeline-state ${ready ? "ready" : ""}`}>
        {state}
      </div>
    </div>
  );
}

function ThreatBadge({
  active,
  known,
}: {
  active: boolean;
  known: boolean;
}) {
  if (active) {
    return (
      <span className="threat-tag danger">
        <AlertTriangle size={11} />
        Active exploitation
      </span>
    );
  }

  if (known) {
    return (
      <span className="threat-tag warning">
        <Wifi size={11} />
        Known exploit
      </span>
    );
  }

  return (
    <span className="threat-tag safe">
      <ShieldCheck size={11} />
      No active signal
    </span>
  );
}


