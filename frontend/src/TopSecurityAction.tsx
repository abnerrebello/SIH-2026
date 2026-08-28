import { useState } from "react";
import {
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  GitBranch,
  ShieldAlert,
  Zap,
} from "lucide-react";
import { Link } from "react-router-dom";

import { api, type PriorityResult } from "./lib/api";

export default function TopSecurityAction({
  item,
}: {
  item?: PriorityResult;
}) {
  const [loading, setLoading] = useState(false);
  const [simulation, setSimulation] =
    useState<Awaited<
      ReturnType<typeof api.patchImpact>
    > | null>(null);

  if (!item) {
    return null;
  }

  async function simulate() {
    setLoading(true);

    try {
      const result = await api.patchImpact(
        item.vulnerability_id,
      );

      setSimulation(result);
    } catch (error) {
      console.error(
        "Unable to simulate patch impact:",
        error,
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="top-security-action">
      <div className="top-security-action-main">
        <div className="eyebrow">
          <Zap size={14} />
          TOP SECURITY ACTION
        </div>

        <div className="top-security-action-title-row">
          <div>
            <div className="mono top-security-cve">
              {item.cve_id}
            </div>

            <h2>{item.title}</h2>

            <p>
              Patch this vulnerability first because it currently
              creates the greatest contextual exposure in the
              environment.
            </p>
          </div>

          <div className="top-security-score">
            <span>RISK</span>
            <strong>
              {Math.round(item.risk_score)}
            </strong>
            <small>/100</small>
          </div>
        </div>

        <div className="top-security-meta">
          <div>
            <GitBranch size={14} />
            <span>
              {item.attack_path_count} attack paths
            </span>
          </div>

          <div>
            <ShieldAlert size={14} />
            <span>
              {item.critical_targets_reached} critical targets
            </span>
          </div>

          {item.choke_point && (
            <div>
              <Zap size={14} />
              <span>Choke point</span>
            </div>
          )}
        </div>
      </div>

      <div className="top-security-action-side">
        <div className="expected-impact-label">
          EXPECTED IMPACT
        </div>

        {simulation ? (
          <div className="top-security-result">
            <div>
              <span>Attack paths</span>
              <strong>
                {simulation.before.attack_paths}
                <ChevronRight size={13} />
                <em>
                  {simulation.after.attack_paths}
                </em>
              </strong>
            </div>

            <div>
              <span>Critical paths</span>
              <strong>
                {simulation.before.critical_attack_paths}
                <ChevronRight size={13} />
                <em>
                  {simulation.after.critical_attack_paths}
                </em>
              </strong>
            </div>

            <div className="result-success">
              <CheckCircle2 size={15} />
              <span>
                {simulation.impact.eliminated_paths} paths
                eliminated
              </span>
            </div>
          </div>
        ) : (
          <button
            className="top-security-simulate"
            onClick={simulate}
            disabled={loading}
          >
            {loading
              ? "Simulating..."
              : "Simulate Patch Impact"}
            <ChevronRight size={14} />
          </button>
        )}

        <Link
          to={`/prioritization/${item.vulnerability_id}`}
          className="top-security-investigate"
        >
          Investigate vulnerability
          <ArrowUpRight size={14} />
        </Link>
      </div>
    </section>
  );
}


