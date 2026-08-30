import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  ArrowDownRight,
  ArrowRight,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Gauge,
  Shield,
  ShieldCheck,
  Sparkles,
  Target,
  TrendingDown,
  Users,
  Zap,
} from "lucide-react";

import {
  api,
  type InvestmentOptimization,
} from "./lib/api";

function formatCurrency(value: number) {
  return new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  }).format(value);
}

function formatCompactCurrency(value: number) {
  if (value >= 10000000) {
    return `₹${(value / 10000000).toFixed(1)}Cr`;
  }

  if (value >= 100000) {
    return `₹${(value / 100000).toFixed(1)}L`;
  }

  if (value >= 1000) {
    return `₹${(value / 1000).toFixed(0)}K`;
  }

  return formatCurrency(value);
}

const scenarioBudgets = [
  200000,
  500000,
  1000000,
  2500000,
];

export default function InvestmentOptimizerPage() {
  const [budget, setBudget] = useState(1000000);
  const [engineers, setEngineers] = useState(3);
  const [days, setDays] = useState(14);

  const [result, setResult] =
    useState<InvestmentOptimization | null>(null);

  const [scenarios, setScenarios] = useState<
    {
      budget: number;
      result: InvestmentOptimization;
    }[]
  >([]);

  const mutation = useMutation({
    mutationFn: () =>
      api.investmentOptimize(
        budget,
        engineers,
        days,
      ),
    onSuccess: setResult,
  });

  const scenarioMutation = useMutation({
    mutationFn: async () => {
      const results = await Promise.all(
        scenarioBudgets.map(async (scenarioBudget) => ({
          budget: scenarioBudget,
          result: await api.investmentOptimize(
            scenarioBudget,
            engineers,
            days,
          ),
        })),
      );

      return results;
    },
    onSuccess: setScenarios,
  });

  const optimize = () => {
    mutation.mutate();
  };

  const compareScenarios = () => {
    scenarioMutation.mutate();
  };

  const setScenario = (
    scenarioBudget: number,
    scenarioEngineers: number,
    scenarioDays: number,
  ) => {
    setBudget(scenarioBudget);
    setEngineers(scenarioEngineers);
    setDays(scenarioDays);
    setResult(null);
  };

  return (
    <div className="page-stack investment-page">
      <section className="investment-hero">
        <div className="investment-hero-content">
          <div className="eyebrow investment-eyebrow">
            SINGULARITY DECISION ENGINE
          </div>

          <h1>Investment Optimizer</h1>

          <p>
            Maximize cybersecurity risk reduction
            with the resources you actually have.
          </p>

          <div className="investment-hero-line">
            <Sparkles size={15} />
            <span>
              Security impact · Cost · People · Time · Attack paths
            </span>
          </div>
        </div>

        <div className="investment-hero-badge">
          <ShieldCheck size={24} />
          <span>
            <strong>SIH26105</strong>
            Security Investment Optimization
          </span>
        </div>
      </section>

      <section className="investment-workbench">
        <div className="investment-workbench-header">
          <div>
            <div className="panel-title">
              Define your security constraints
            </div>

            <div className="panel-subtitle">
              Singularity searches for the highest-impact
              remediation combination within these limits.
            </div>
          </div>

          <button
            type="button"
            className="investment-optimize-button"
            onClick={optimize}
            disabled={mutation.isPending}
          >
            <Zap size={16} />

            {mutation.isPending
              ? "Optimizing..."
              : "Find Optimal Plan"}
          </button>
        </div>

        <div className="investment-input-grid">
          <ConstraintInput
            icon={<CircleDollarSign size={18} />}
            label="Security budget"
            value={budget}
            prefix="₹"
            onChange={setBudget}
            min={10000}
            step={10000}
            formatValue={(value) =>
              value.toLocaleString("en-IN")
            }
          />

          <ConstraintInput
            icon={<Users size={18} />}
            label="Security engineers"
            value={engineers}
            suffix="people"
            onChange={setEngineers}
            min={1}
            step={1}
          />

          <ConstraintInput
            icon={<Clock3 size={18} />}
            label="Remediation window"
            value={days}
            suffix="days"
            onChange={setDays}
            min={1}
            step={1}
          />
        </div>

        <div className="investment-scenarios">
          <span>Quick scenarios</span>

          <button
            type="button"
            onClick={() =>
              setScenario(200000, 2, 7)
            }
          >
            ₹2L · 2 engineers · 7 days
          </button>

          <button
            type="button"
            onClick={() =>
              setScenario(500000, 3, 14)
            }
          >
            ₹5L · 3 engineers · 14 days
          </button>

          <button
            type="button"
            onClick={() =>
              setScenario(1000000, 3, 14)
            }
          >
            ₹10L · 3 engineers · 14 days
          </button>

          <button
            type="button"
            onClick={() =>
              setScenario(2500000, 5, 30)
            }
          >
            ₹25L · 5 engineers · 30 days
          </button>
        </div>

        <div className="investment-scenario-action">
          <button
            type="button"
            onClick={compareScenarios}
            disabled={scenarioMutation.isPending}
            className="investment-secondary-button"
          >
            <Target size={15} />

            {scenarioMutation.isPending
              ? "Comparing scenarios..."
              : "Compare Budget Scenarios"}
          </button>

          <span>
            Compare the same 3-engineer, 14-day environment
            across four investment levels.
          </span>
        </div>

        {mutation.isError && (
          <div className="investment-error">
            Unable to calculate the security investment plan.
            Make sure the Singularity security API is operational.
          </div>
        )}
      </section>

      {!result && !mutation.isPending && (
        <section className="investment-empty-state">
          <div className="investment-empty-icon">
            <Target size={28} />
          </div>

          <div>
            <h2>Ready to optimize your security spend</h2>
            <p>
              Set your constraints above and let Singularity
              evaluate the available remediation actions.
            </p>
          </div>

          <ArrowRight size={20} />
        </section>
      )}

      {scenarios.length === 4 && (
        <ScenarioLab
          scenarios={scenarios}
          onSelect={(scenario) => {
            setBudget(scenario.budget);
            setResult(scenario.result);
          }}
        />
      )}

      {result && (
        <>
          <section id="investment-plan-result" className="investment-command-summary">
            <div className="investment-risk-overview">
              <div className="investment-risk-before">
                <span>Current environment risk</span>
                <strong>
                  {Math.round(result.current_risk)}
                </strong>
                <small>/ 100</small>
              </div>

              <ArrowDownRight
                size={30}
                className="investment-flow-arrow"
              />

              <div className="investment-risk-after">
                <span>Optimized residual risk</span>
                <strong>
                  {Math.round(result.optimized_risk)}
                </strong>
                <small>/ 100</small>
              </div>

              <div className="investment-risk-delta">
                <TrendingDown size={18} />

                <div>
                  <span>Risk reduction</span>
                  <strong>
                    {result.risk_reduction.toFixed(1)}%
                  </strong>
                </div>
              </div>
            </div>

            <div className="investment-constraint-summary">
              <ConstraintSummary
                icon={<CircleDollarSign size={15} />}
                label="Investment"
                value={formatCompactCurrency(
                  result.investment,
                )}
                detail={`${formatCompactCurrency(
                  result.budget_remaining,
                )} remaining`}
              />

              <ConstraintSummary
                icon={<Users size={15} />}
                label="People"
                value={`${result.engineers_used}`}
                detail={`of ${engineers} engineers`}
              />

              <ConstraintSummary
                icon={<Clock3 size={15} />}
                label="Timeline"
                value={`${result.days_used}`}
                detail={`of ${days} days`}
              />

              <ConstraintSummary
                icon={<GitBranchIcon />}
                label="Attack paths"
                value={`${result.attack_paths_before - result.attack_paths_after}`}
                detail="eliminated"
              />
            </div>
          </section>

          <section className="investment-scoreboard">
            <div className="investment-scoreboard-title">
              <div>
                <div className="panel-title">
                  Security Impact
                </div>

                <div className="panel-subtitle">
                  How the recommended plan changes the
                  attack surface.
                </div>
              </div>

              <div className="investment-impact-pill">
                <Shield size={14} />
                {result.security_impact.toFixed(1)}%
                exposure reduction
              </div>
            </div>

            <div className="investment-impact-grid">
              <ImpactCard
                label="Attack paths"
                before={result.attack_paths_before}
                after={result.attack_paths_after}
              />

              <ImpactCard
                label="Critical paths"
                before={result.critical_paths_before}
                after={result.critical_paths_after}
              />

              <div className="investment-exposure-card">
                <span>Weighted exposure</span>

                <div className="exposure-values">
                  <strong>
                    {result.exposure_before?.toFixed(0) ?? "—"}
                  </strong>

                  <ArrowRight size={16} />

                  <strong>
                    {result.exposure_after?.toFixed(0) ?? "—"}
                  </strong>
                </div>

                <small>
                  Attack-graph exposure index
                </small>
              </div>
            </div>
          </section>

          <section className="investment-plan">
            <div className="investment-section-heading">
              <div>
                <div className="panel-title">
                  Optimal Security Investment Plan
                </div>

                <div className="panel-subtitle">
                  Actions selected for the highest joint
                  environmental impact.
                </div>
              </div>

              <div className="investment-plan-status">
                <CheckCircle2 size={15} />
                Optimization complete
              </div>
            </div>

            <div className="investment-actions-list">
              {result.actions.map((action, index) => (
                <article
                  className="investment-action-card"
                  key={`${action.vulnerability_id}-${action.asset_id}`}
                >
                  <div className="investment-action-rank">
                    <span>STEP</span>
                    <strong>
                      {String(index + 1).padStart(2, "0")}
                    </strong>
                  </div>

                  <div className="investment-action-content">
                    <div className="investment-action-heading">
                      <div>
                        <span className="investment-cve">
                          {action.cve_id}
                        </span>

                        <h3>{action.title}</h3>

                        <div className="investment-asset">
                          {action.asset_name}
                        </div>
                      </div>

                      <div className="investment-impact-number">
                        <span>Security impact</span>
                        <strong>
                          +{action.security_impact.toFixed(1)}%
                        </strong>
                      </div>
                    </div>

                    <div className="investment-action-details">
                      <ActionStat
                        label="Investment"
                        value={formatCurrency(
                          action.estimated_cost,
                        )}
                        icon={<CircleDollarSign size={13} />}
                      />

                      <ActionStat
                        label="Effort"
                        value={`${action.estimated_days} days`}
                        icon={<Clock3 size={13} />}
                      />

                      <ActionStat
                        label="Engineers"
                        value={`${action.estimated_engineers}`}
                        icon={<Users size={13} />}
                      />

                      <ActionStat
                        label="Paths removed"
                        value={`${action.eliminated_paths}`}
                        icon={<GitBranchIcon />}
                      />

                      <ActionStat
                        label="Critical paths"
                        value={`${action.eliminated_critical_paths}`}
                        icon={<ShieldCheck size={13} />}
                      />

                      <ActionStat
                        label="Value / ₹1K"
                        value={action.value_per_1000.toFixed(2)}
                        icon={<Gauge size={13} />}
                      />
                    </div>
                  </div>
                </article>
              ))}
            </div>
          </section>

          {result.actions.length > 0 && (
            <section className="investment-explanation">
              <div className="investment-explanation-icon">
                <Sparkles size={20} />
              </div>

              <div>
                <strong>Why this plan?</strong>

                <p>
                  Singularity selected these actions by jointly
                  evaluating attack-path exposure, critical
                  targets, remediation cost, staffing and time
                  constraints instead of ranking vulnerabilities
                  by CVSS alone.
                </p>
              </div>
            </section>
          )}

          {result.alternatives.length > 0 && (
            <section className="investment-alternatives-section">
              <div className="investment-section-heading">
                <div>
                  <div className="panel-title">
                    High-Value Alternatives
                  </div>

                  <div className="panel-subtitle">
                    Strong investments that fell outside the
                    optimal combination.
                  </div>
                </div>
              </div>

              <div className="investment-alternatives-list">
                {result.alternatives.map(
                  (alternative) => (
                    <div
                      className="investment-alternative-row"
                      key={`${alternative.vulnerability_id}-${alternative.asset_id}-${alternative.cve_id}`}
                    >
                      <div className="investment-alternative-main">
                        <span className="investment-cve">
                          {alternative.cve_id}
                        </span>

                        <strong>
                          {alternative.asset_name}
                        </strong>
                      </div>

                      <div>
                        <span>Impact</span>
                        <strong>
                          {alternative.security_impact.toFixed(1)}%
                        </strong>
                      </div>

                      <div>
                        <span>Cost</span>
                        <strong>
                          {formatCompactCurrency(
                            alternative.estimated_cost,
                          )}
                        </strong>
                      </div>

                      <div>
                        <span>Value / ₹1K</span>
                        <strong>
                          {alternative.value_per_1000.toFixed(2)}
                        </strong>
                      </div>
                    </div>
                  ),
                )}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}

function ScenarioLab({
  scenarios,
  onSelect,
}: {
  scenarios: {
    budget: number;
    result: InvestmentOptimization;
  }[];
  onSelect: (scenario: {
    budget: number;
    result: InvestmentOptimization;
  }) => void;
}) {
  const [selectedBudget, setSelectedBudget] =
    useState<number | null>(null);

  const sorted = [...scenarios].sort(
    (a, b) => a.budget - b.budget,
  );

  const handleSelect = (scenario: {
    budget: number;
    result: InvestmentOptimization;
  }) => {
    setSelectedBudget(scenario.budget);
    onSelect(scenario);

    window.setTimeout(() => {
      document
        .getElementById("investment-plan-result")
        ?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
    }, 50);
  };

  return (
    <section className="scenario-lab">
      <div className="scenario-lab-header">
        <div>
          <div className="eyebrow">
            WHAT-IF ANALYSIS
          </div>

          <h2>Scenario Lab</h2>

          <p>
            Compare how different security budgets change
            the recommended investment strategy.
          </p>
        </div>

        <div className="scenario-lab-constraint">
          {3} engineers · {14} days
        </div>
      </div>

      <div className="scenario-cards">
        {sorted.map((scenario) => {
          const isSelected =
            selectedBudget === scenario.budget;

          const result = scenario.result;

          return (
            <button
              type="button"
              className={
                isSelected
                  ? "scenario-card scenario-card-selected"
                  : "scenario-card"
              }
              key={scenario.budget}
              onClick={() =>
                handleSelect(scenario)
              }
              aria-pressed={isSelected}
            >
              <div className="scenario-card-header">
                <span>
                  {formatCompactCurrency(
                    scenario.budget,
                  )}
                </span>

                {isSelected && (
                  <CheckCircle2 size={15} />
                )}
              </div>

              <strong>
                {Math.round(
                  result.optimized_risk,
                )}
              </strong>

              <small>
                residual organizational risk
              </small>

              <div className="scenario-reduction">
                <TrendingDown size={13} />
                {result.risk_reduction.toFixed(1)}%
                reduction
              </div>

              <div className="scenario-bar">
                <div
                  style={{
                    width: `${Math.max(
                      0,
                      Math.min(
                        result.risk_reduction,
                        100,
                      ),
                    )}%`,
                  }}
                />
              </div>

              <div className="scenario-card-footer">
                <span>
                  {result.attack_paths_before -
                    result.attack_paths_after}{" "}
                  paths removed
                </span>

                <span>
                  {formatCompactCurrency(
                    result.investment,
                  )}{" "}
                  used
                </span>
              </div>

              <div className="scenario-card-action">
                {isSelected
                  ? "Selected plan"
                  : "Load this plan →"}
              </div>
            </button>
          );
        })}
      </div>

      <div className="scenario-table">
        <div className="scenario-table-head">
          <span>Budget</span>
          <span>Investment</span>
          <span>Residual risk</span>
          <span>Risk reduction</span>
          <span>Paths removed</span>
        </div>

        {sorted.map((scenario) => (
          <button
            type="button"
            className={
              selectedBudget === scenario.budget
                ? "scenario-table-row scenario-table-row-selected"
                : "scenario-table-row"
            }
            key={scenario.budget}
            onClick={() =>
              handleSelect(scenario)
            }
          >
            <strong>
              {formatCompactCurrency(
                scenario.budget,
              )}
            </strong>

            <span>
              {formatCompactCurrency(
                scenario.result.investment,
              )}
            </span>

            <span>
              {Math.round(
                scenario.result.optimized_risk,
              )}
            </span>

            <span className="scenario-positive">
              {scenario.result.risk_reduction.toFixed(1)}%
            </span>

            <span>
              {scenario.result.attack_paths_before -
                scenario.result.attack_paths_after}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
function ConstraintInput({
  icon,
  label,
  value,
  prefix,
  suffix,
  onChange,
  min,
  step,
  formatValue,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  prefix?: string;
  suffix?: string;
  onChange: (value: number) => void;
  min: number;
  step: number;
  formatValue?: (value: number) => string;
}) {
  return (
    <label className="investment-constraint">
      <span className="investment-constraint-label">
        {icon}
        {label}
      </span>

      <div className="investment-constraint-field">
        {prefix && (
          <span className="constraint-prefix">
            {prefix}
          </span>
        )}

        <input
          type="number"
          min={min}
          step={step}
          value={value}
          onChange={(event) =>
            onChange(
              Math.max(
                min,
                Number(event.target.value),
              ),
            )
          }
        />

        {suffix && (
          <span className="constraint-suffix">
            {suffix}
          </span>
        )}
      </div>

      {formatValue && (
        <small>
          {formatValue(value)}
        </small>
      )}
    </label>
  );
}

function ConstraintSummary({
  icon,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="investment-constraint-summary-card">
      <div>
        {icon}
        <span>{label}</span>
      </div>

      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function ImpactCard({
  label,
  before,
  after,
}: {
  label: string;
  before: number;
  after: number;
}) {
  const removed = Math.max(
    before - after,
    0,
  );

  const percent =
    before > 0
      ? (removed / before) * 100
      : 0;

  return (
    <div className="investment-impact-card">
      <span>{label}</span>

      <div className="impact-card-values">
        <strong>{before}</strong>
        <ArrowRight size={16} />
        <strong>{after}</strong>
      </div>

      <div className="impact-progress">
        <div
          style={{
            width: `${Math.min(percent, 100)}%`,
          }}
        />
      </div>

      <small>
        {removed} removed · {percent.toFixed(0)}%
      </small>
    </div>
  );
}

function ActionStat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="investment-action-stat">
      <div>
        {icon}
        <span>{label}</span>
      </div>

      <strong>{value}</strong>
    </div>
  );
}

function GitBranchIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="6" y1="3" x2="6" y2="15" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="6" cy="18" r="3" />
      <path d="M18 9a9 9 0 0 1-9 9" />
    </svg>
  );
}

