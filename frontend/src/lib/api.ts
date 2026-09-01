const API_BASE = "http://localhost:8000/api/v1";

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });

  if (!response.ok) {
    const message = await response.text().catch(
      () => "Unknown API error",
    );

    throw new Error(`${response.status}: ${message}`);
  }

  return response.json() as Promise<T>;
}

/* =========================================================
   TYPES
========================================================= */

export interface Asset {
  id: number;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
  operating_system: string | null;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  internet_exposed: boolean;
  description: string | null;
  created_at: string;
}

export interface Vulnerability {
  id: number;
  cve_id: string;
  title: string;
  description: string | null;
  cvss_score: number;
  severity:
    | "NONE"
    | "LOW"
    | "MEDIUM"
    | "HIGH"
    | "CRITICAL";
  exploitability_score: number | null;
  actively_exploited: boolean;
  known_exploit: boolean;
  remediation: string | null;
  created_at: string;
}

export interface NetworkRelationship {
  id: number;
  source_asset_id: number;
  target_asset_id: number;
  relationship_type: string;
  trust_level: string;
}

export interface AttackPath {
  source_asset_id: number;
  target_asset_id: number;
  asset_ids: number[];
  asset_names: string[];
  vulnerabilities: string[];
  path_length: number;
  target_criticality: string;
  risk_score: number;
  choke_points: number[];
}

export interface AttackPathsResponse {
  paths: AttackPath[];
  choke_points: {
    asset_id: number;
    asset_name: string;
    criticality: string;
    path_count: number;
    vulnerabilities: string[];
  }[];
  path_count: number;
}

export interface NetworkGraphResponse {
  nodes: {
    id: number;
    name: string;
    asset_type: string;
    criticality: string;
    internet_exposed: boolean;
  }[];

  edges: {
    source: number;
    target: number;
    relationship_type: string;
    trust_level: string;
  }[];

  choke_points: {
    asset_id: number;
    asset_name: string;
    criticality: string;
    path_count: number;
    vulnerabilities: string[];
  }[];
}

export interface PriorityResult {
  rank: number;
  vulnerability_id: number;
  cve_id: string;
  title: string;
  asset_id: number;
  asset_name: string;
  cvss_score: number;
  cvss_priority: string;
  risk_score: number;
  priority: string;
  attack_path_count: number;
  critical_targets_reached: number;
  choke_point: boolean;
  reasons: string[];
  score_breakdown: Record<string, number>;
}

export interface PrioritiesResponse {
  count: number;
  results: PriorityResult[];
}

export interface RiskSummary {
  overall_risk_score: number;
  average_risk_score: number;
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/* =========================================================
   VULNERABILITY INVESTIGATION
========================================================= */

export interface PriorityDetail {
  vulnerability_id: number;
  cve_id: string;
  title: string;
  description: string | null;
  remediation: string | null;

  asset_id: number;
  asset_name: string;

  cvss_score: number;
  risk_score: number;

  priority: string;
  cvss_priority: string;

  attack_path_count: number;
  critical_targets_reached: number;
  choke_point: boolean;

  reasons: string[];

  score_breakdown: Record<string, number>;

  attack_paths: {
    source_asset_id: number;
    target_asset_id: number;
    asset_names: string[];
    risk_score: number;
    path_length: number;
    target_criticality: string;
    choke_points: number[];
  }[];
}

export interface PatchImpact {
  vulnerability_id: number;
  cve_id: string;

  before: {
    attack_paths: number;
    critical_attack_paths: number;
    risk_score: number;
  };

  after: {
    attack_paths: number;
    critical_attack_paths: number;
    risk_score: number;
  };

  impact: {
    eliminated_paths: number;
    eliminated_critical_paths: number;
    risk_reduction: number;
  };
}

/* =========================================================
   API
========================================================= */

export interface InvestmentAction {
    action_id: string;
    action_type: "PATCH" | "SEGMENT" | "ISOLATE";

    vulnerability_id?: number | null;
    asset_id?: number | null;

    source_asset_id?: number | null;
    target_asset_id?: number | null;

    cve_id?: string | null;
    title?: string;
    asset_name: string;
    action_label?: string;

    current_risk: number;
    security_impact: number;

    eliminated_paths: number;
    eliminated_critical_paths: number;

    estimated_cost: number;
    estimated_days: number;
    estimated_engineers: number;

    value_per_1000: number;
    value_per_100000: number;

    selection_reason?: string | null;
    rejection_reason?: string | null;
}

export interface InvestmentAlternative {
    action_id: string;
    action_type: "PATCH" | "SEGMENT" | "ISOLATE";

    vulnerability_id?: number | null;
    asset_id?: number | null;

    source_asset_id?: number | null;
    target_asset_id?: number | null;

    cve_id?: string | null;
    title?: string;
    asset_name: string;
    action_label?: string;

    security_impact: number;
    estimated_cost: number;
    estimated_days?: number;
    estimated_engineers?: number;

    value_per_1000: number;
    value_per_100000: number;

    selection_reason?: string | null;
    rejection_reason?: string | null;
}

export interface InvestmentOptimization {
    current_risk: number;
    optimized_risk: number;
    risk_reduction: number;

    investment: number;
    budget_remaining: number;

    engineers_used: number;
    days_used: number;

    security_impact: number;

    attack_paths_before: number;
    attack_paths_after: number;

    critical_paths_before: number;
    critical_paths_after: number;

    exposure_before?: number;
    exposure_after?: number;

    current_eal: number;
    optimized_eal: number;
    financial_exposure_avoided: number;
    rosi: number;

    actions: InvestmentAction[];
    alternatives: InvestmentAlternative[];
}
export const api = {
  investmentOptimize: (
    budget: number,
    engineers: number,
    days: number,
  ) =>
    request<InvestmentOptimization>(
      "/investment/optimize",
      {
        method: "POST",
        body: JSON.stringify({
          budget,
          engineers,
          days,
        }),
      },
    ),
  importEnvironment: async (file: File) => {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(
      `${API_BASE}/import/environment`,
      {
        method: "POST",
        body: formData,
      },
    );

    if (!response.ok) {
      const message = await response.text().catch(
        () => "Environment import failed",
      );

      throw new Error(
        `${response.status}: ${message}`,
      );
    }

    return response.json();
  },

  assets: () =>
    request<Asset[]>("/assets"),

  vulnerabilities: () =>
    request<Vulnerability[]>("/vulnerabilities"),

  network: () =>
    request<NetworkRelationship[]>("/network"),

  attackPaths: () =>
    request<AttackPathsResponse>("/attack-paths"),

  graph: () =>
    request<NetworkGraphResponse>("/network/graph"),

  priorities: () =>
    request<PrioritiesResponse>("/priorities"),

  riskSummary: () =>
    request<RiskSummary>("/risk-summary"),

  priorityDetail: (id: number, assetId?: number) =>
    request<PriorityDetail>(
      `/priorities/${id}${assetId ? `?asset_id=${assetId}` : ""}`,
    ),

  patchImpact: (id: number, assetId?: number) =>
    request<PatchImpact>(
      `/simulations/patch-impact/${id}${
        assetId !== undefined
          ? `?asset_id=${assetId}`
          : ""
      }`,
      {
        method: "POST",
      },
    ),
};







