import { getStoredUser } from "./lib/auth";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  ChevronRight,
  Info,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "./lib/api";


interface ComparisonResponse {
  cvss_ranking: {
    rank: number;
    cve_id: string;
    cvss_score: number;
    asset_name: string;
  }[];

  singularity_ranking: {
    rank: number;
    cve_id: string;
    risk_score: number;
    priority: string;
    asset_name: string;
  }[];

  ranking_changes: {
    cve_id: string;
    cvss_rank: number;
    singularity_rank: number;
    rank_change: number;
  }[];
}

export default function PrioritizationComparisonPage() {
  const query = useQuery({
    queryKey: ["prioritization-comparison", getStoredUser()?.id],    queryFn: async () => {
      return (await api.prioritizationComparison()) as ComparisonResponse;
    },
  });

  if (query.isLoading) {
    return (
      <div className="state-card">
        <div className="loader" />
        <strong>Building prioritization comparison...</strong>
        <span>
          Comparing CVSS severity with Singularity contextual risk.
        </span>
      </div>
    );
  }

  if (query.error || !query.data) {
    return (
      <div className="state-card error-state">
        <ShieldAlert size={24} />
        <strong>
          Unable to load prioritization comparison.
        </strong>
        <span>
          Verify that the Singularity API is running on port 8000.
        </span>
      </div>
    );
  }

  const data = query.data;

  const changedRankings = data.ranking_changes.filter(
    (item) => item.rank_change !== 0,
  );

  return (
    <div className="page-stack comparison-page">
      <section className="page-intro">
        <div className="eyebrow">
          <Sparkles size={14} />
          SINGULARITY DIFFERENTIATOR
        </div>

        <h2>Severity is not the same as risk.</h2>

        <p>
          CVSS describes technical severity. Singularity adds
          environmental context to determine which weakness should
          actually be remediated first.
        </p>
      </section>

      <section className="comparison-hero">
        <div className="comparison-hero-icon">
          <BarChart3 size={25} />
        </div>

        <div>
          <div className="comparison-hero-label">
            CONTEXT-AWARE PRIORITIZATION
          </div>

          <h2>
            The highest-CVSS vulnerability is not necessarily
            the highest-risk vulnerability.
          </h2>

          <p>
            Singularity considers exploitability, internet exposure,
            asset criticality, attack-path impact, critical targets,
            and choke-point position alongside CVSS.
          </p>
        </div>
      </section>

      <section className="comparison-grid">
        <RankingPanel
          title="Traditional CVSS"
          subtitle="Severity-only ranking"
          icon={<ShieldAlert size={17} />}
          tone="neutral"
          items={data.cvss_ranking}
          type="cvss"
        />

        <RankingPanel
          title="Singularity"
          subtitle="Contextual risk ranking"
          icon={<ShieldCheck size={17} />}
          tone="aegis"
          items={data.singularity_ranking}
          type="risk"
        />
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              Where the ranking changes
            </div>

            <div className="panel-subtitle">
              Environmental context can change remediation priority.
            </div>
          </div>

          <div className="banner-chip">
            <Info size={14} />
            {changedRankings.length} ranking changes
          </div>
        </div>

        <div className="ranking-change-list">
          {data.ranking_changes.map((item) => (
            <RankingChangeRow
              key={item.cve_id}
              item={item}
            />
          ))}
        </div>
      </section>

      <section className="comparison-explanation">
        <div className="comparison-explanation-header">
          <Sparkles size={18} />

          <div>
            <strong>Why Singularity is different</strong>

            <span>
              Context turns a vulnerability list into an actionable
              security decision.
            </span>
          </div>
        </div>

        <div className="comparison-factor-grid">
          <Factor
            title="Asset criticality"
            description="A weakness on a production database matters more than the same weakness on a low-value endpoint."
          />

          <Factor
            title="Attack-path impact"
            description="A vulnerability appearing across multiple routes can have a larger security effect."
          />

          <Factor
            title="Internet exposure"
            description="Internet-facing systems provide a more direct attacker entry point."
          />

          <Factor
            title="Threat context"
            description="Known exploits and active exploitation increase urgency beyond raw CVSS."
          />

          <Factor
            title="Critical targets"
            description="Reaching identity infrastructure or production databases increases impact."
          />

          <Factor
            title="Choke points"
            description="Fixing a strategically placed weakness can eliminate multiple routes."
          />
        </div>
      </section>

      <section className="comparison-cta">
        <div>
          <div className="eyebrow">
            <CheckCircle2 size={14} />
            ACTIONABLE OUTPUT
          </div>

          <h2>Stop asking "Which CVE is highest?"</h2>

          <p>
            Start asking "Which weakness creates the greatest
            exposure in this environment?"
          </p>
        </div>

        <Link
          to="/prioritization"
          className="primary-button"
        >
          View remediation priorities
          <ArrowUpRight size={15} />
        </Link>
      </section>
    </div>
  );
}

function RankingPanel({
  title,
  subtitle,
  icon,
  tone,
  items,
  type,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  tone: "neutral" | "aegis";
  items:
    | {
        rank: number;
        cve_id: string;
        cvss_score: number;
        asset_name: string;
      }[]
    | {
        rank: number;
        cve_id: string;
        risk_score: number;
        priority: string;
        asset_name: string;
      }[];
  type: "cvss" | "risk";
}) {
  return (
    <section className={`ranking-panel ${tone}`}>
      <div className="ranking-panel-header">
        <div className="ranking-title">
          <div className="ranking-icon">
            {icon}
          </div>

          <div>
            <strong>{title}</strong>
            <span>{subtitle}</span>
          </div>
        </div>
      </div>

      <div className="ranking-list">
        {items.map((item) => {
          const score =
            type === "cvss"
              ? (
                  item as {
                    cvss_score: number;
                  }
                ).cvss_score
              : (
                  item as {
                    risk_score: number;
                  }
                ).risk_score;

          const priority =
            type === "risk"
              ? (
                  item as {
                    priority: string;
                  }
                ).priority
              : undefined;

          return (
            <div
              className="ranking-item"
              key={item.cve_id}
            >
              <div className="ranking-number">
                #{item.rank}
              </div>

              <div className="ranking-main">
                <div className="ranking-cve">
                  {item.cve_id}
                </div>

                <div className="ranking-asset">
                  {item.asset_name}
                </div>
              </div>

              <div className="ranking-score">
                <strong>
                  {Number(score).toFixed(
                    type === "cvss" ? 1 : 0,
                  )}
                </strong>

                <span>
                  {priority ??
                    (type === "cvss"
                      ? "CVSS"
                      : "Risk")}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function RankingChangeRow({
  item,
}: {
  item: ComparisonResponse["ranking_changes"][number];
}) {
  const improved = item.rank_change > 0;
  const worsened = item.rank_change < 0;
  const unchanged = item.rank_change === 0;

  return (
    <div className="ranking-change-row">
      <div className="change-cve mono">
        {item.cve_id}
      </div>

      <div className="change-flow">
        <span className="change-rank">
          CVSS #{item.cvss_rank}
        </span>

        <ChevronRight size={15} />

        <span className="change-rank aegis-rank">
          Singularity #{item.singularity_rank}
        </span>
      </div>

      <div
        className={`rank-change ${
          improved
            ? "positive"
            : worsened
              ? "negative"
              : "neutral"
        }`}
      >
        {improved && <ArrowUp size={14} />}
        {worsened && <ArrowDown size={14} />}

        <span>
          {unchanged
            ? "No change"
            : improved
              ? `${item.rank_change} position${
                  item.rank_change === 1
                    ? ""
                    : "s"
                } higher`
              : `${Math.abs(item.rank_change)} position${
                  Math.abs(item.rank_change) === 1
                    ? ""
                    : "s"
                } lower`}
        </span>
      </div>
    </div>
  );
}

function Factor({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="factor-card">
      <div className="factor-check">
        <CheckCircle2 size={14} />
      </div>

      <div>
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
    </div>
  );
}





