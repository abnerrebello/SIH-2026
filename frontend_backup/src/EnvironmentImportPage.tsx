import {
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
} from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileText,
  ShieldCheck,
  Upload,
  GitBranch,
  Activity,
} from "lucide-react";

import { api } from "./lib/api";

interface ImportResult {
  filename: string;
  assets_created: number;
  assets_updated: number;
  vulnerabilities_created: number;
  vulnerabilities_updated: number;
  relationships_created: number;
  mappings_created: number;
  errors: string[];
}

interface AnalysisResult {
  overallRisk: number;
  averageRisk: number;
  totalVulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  attackPaths: number;
  topPriority: string | null;
}

export default function EnvironmentImportPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");

  const selectFile = (selected: File | null) => {
    if (!selected) return;

    setResult(null);
    setAnalysis(null);
    setError("");

    if (!selected.name.toLowerCase().endsWith(".csv")) {
      setFile(null);
      setError("Please select a CSV file.");
      return;
    }

    if (selected.size > 5 * 1024 * 1024) {
      setFile(null);
      setError("CSV files must be smaller than 5 MB.");
      return;
    }

    setFile(selected);
  };

  const handleFileChange = (
    event: ChangeEvent<HTMLInputElement>,
  ) => {
    selectFile(event.target.files?.[0] ?? null);
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    selectFile(event.dataTransfer.files?.[0] ?? null);
  };

  const handleImport = async () => {
    if (!file) {
      setError("Select a CSV file before importing.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setAnalysis(null);

    try {
      const imported = await api.importEnvironment(file);

      await Promise.all([
        "risk-summary",
        "attack-paths",
        "priorities",
        "assets",
        "graph-page",
        "attack-paths-page",
        "network-graph",
      ].map((key) => queryClient.invalidateQueries({ queryKey: [key] })));
      setResult(imported as ImportResult);

      setAnalyzing(true);

      const [riskSummary, priorities, attackPaths] =
        await Promise.all([
          api.riskSummary(),
          api.priorities(),
          api.attackPaths(),
        ]);

      const summary = riskSummary as {
        overall_risk_score: number;
        average_risk_score: number;
        total_vulnerabilities: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
      };

      const priorityData = priorities as {
        results?: Array<{
          title?: string;
          priority?: string;
          risk_score?: number;
        }>;
      };

      const pathData = attackPaths as {
        paths?: unknown[];
      };

      setAnalysis({
        overallRisk: summary.overall_risk_score,
        averageRisk: summary.average_risk_score,
        totalVulnerabilities:
          summary.total_vulnerabilities,
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        attackPaths: pathData.paths?.length ?? 0,
        topPriority:
          priorityData.results?.[0]?.title ?? null,
      });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Environment import failed.",
      );
    } finally {
      setLoading(false);
      setAnalyzing(false);
    }
  };

  const downloadTemplate = () => {
    const link = document.createElement("a");
    link.href = "/singularity-rich-environment-template-v2.csv";
    link.download = "singularity-environment-template.csv";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <div className="eyebrow">ENVIRONMENT</div>
          <h1>Import Environment</h1>
          <p>
            Bring your infrastructure into Singularity and
            analyze its security exposure.
          </p>
        </div>
      </div>

      <div className="import-page-grid">
        <section className="panel import-main-panel">
          <div className="import-panel-header">
            <div>
              <h2>Upload security data</h2>
              <p>
                Import assets, vulnerabilities,
                relationships, and vulnerability mappings
                from CSV.
              </p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={downloadTemplate}
            >
              <Download size={16} />
              CSV Template
            </button>
          </div>

          <div
            className={`import-dropzone ${
              dragging ? "dragging" : ""
            } ${file ? "has-file" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".csv,text/csv"
              onChange={handleFileChange}
              hidden
            />

            {file ? (
              <>
                <div className="import-file-icon">
                  <FileText size={28} />
                </div>

                <div className="import-file-name">
                  {file.name}
                </div>

                <div className="import-file-meta">
                  {(file.size / 1024).toFixed(1)} KB Ã‚Â· CSV
                </div>

                <button
                  type="button"
                  className="text-button"
                  onClick={(event) => {
                    event.stopPropagation();
                    setFile(null);
                    setResult(null);
                    setAnalysis(null);
                    setError("");
                  }}
                >
                  Choose another file
                </button>
              </>
            ) : (
              <>
                <div className="import-upload-icon">
                  <Upload size={30} />
                </div>

                <h3>Drop your CSV here</h3>

                <p>
                  or click to browse your computer
                </p>

                <span className="import-helper">
                  CSV only Ã‚Â· maximum 5 MB
                </span>
              </>
            )}
          </div>

          {error && (
            <div className="import-alert error">
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}

          <div className="import-actions">
            <button
              type="button"
              className="primary-button"
              onClick={handleImport}
              disabled={!file || loading}
            >
              <Upload size={17} />
              {loading
                ? "Importing environment..."
                : "Import & Analyze"}
            </button>
          </div>
        </section>

        <aside className="panel import-info-panel">
          <div className="eyebrow">HOW IT WORKS</div>

          <h2>From data to security insight</h2>

          <div className="import-step">
            <div className="step-number">01</div>
            <div>
              <strong>Upload</strong>
              <p>
                Provide your environment inventory as CSV.
              </p>
            </div>
          </div>

          <div className="import-step">
            <div className="step-number">02</div>
            <div>
              <strong>Map</strong>
              <p>
                Singularity connects assets, CVEs, and
                relationships.
              </p>
            </div>
          </div>

          <div className="import-step">
            <div className="step-number">03</div>
            <div>
              <strong>Analyze</strong>
              <p>
                Risk and attack-path engines evaluate the
                imported environment.
              </p>
            </div>
          </div>
        </aside>
      </div>

      {result && (
        <section className="panel import-result-panel">
          <div className="import-success-header">
            <div className="success-icon">
              <CheckCircle2 size={22} />
            </div>

            <div>
              <div className="eyebrow">
                IMPORT COMPLETE
              </div>
              <h2>{result.filename}</h2>
              <p>
                Environment imported successfully.
                {analyzing &&
                  " Running security analysis..."}
              </p>
            </div>
          </div>

          <div className="import-stats">
            <div className="import-stat">
              <span className="stat-value">
                {result.assets_created +
                  result.assets_updated}
              </span>
              <span className="stat-label">Assets</span>
            </div>

            <div className="import-stat">
              <span className="stat-value">
                {result.vulnerabilities_created +
                  result.vulnerabilities_updated}
              </span>
              <span className="stat-label">
                Vulnerabilities
              </span>
            </div>

            <div className="import-stat">
              <span className="stat-value">
                {result.relationships_created}
              </span>
              <span className="stat-label">
                Relationships
              </span>
            </div>

            <div className="import-stat">
              <span className="stat-value">
                {result.mappings_created}
              </span>
              <span className="stat-label">
                Mappings
              </span>
            </div>
          </div>

          {analysis && (
            <div className="environment-analysis">
              <div className="analysis-header">
                <div>
                  <div className="eyebrow">
                    SECURITY ANALYSIS
                  </div>
                  <h2>Environment risk profile</h2>
                </div>

                <div className="analysis-score">
                  <span>{analysis.overallRisk}</span>
                  <small>OVERALL RISK</small>
                </div>
              </div>

              <div className="analysis-grid">
                <div className="analysis-card">
                  <ShieldCheck size={19} />
                  <strong>
                    {analysis.critical}
                  </strong>
                  <span>Critical</span>
                </div>

                <div className="analysis-card">
                  <Activity size={19} />
                  <strong>
                    {analysis.high}
                  </strong>
                  <span>High</span>
                </div>

                <div className="analysis-card">
                  <GitBranch size={19} />
                  <strong>
                    {analysis.attackPaths}
                  </strong>
                  <span>Attack Paths</span>
                </div>

                <div className="analysis-card">
                  <ShieldCheck size={19} />
                  <strong>
                    {analysis.averageRisk}
                  </strong>
                  <span>Average Risk</span>
                </div>
              </div>

              {analysis.topPriority && (
                <div className="top-priority-card">
                  <span>TOP SECURITY PRIORITY</span>
                  <strong>
                    {analysis.topPriority}
                  </strong>
                </div>
              )}
            </div>
          )}

          {result.errors?.length > 0 && (
            <div className="import-alert warning">
              <AlertTriangle size={18} />

              <div>
                <strong>Import warnings</strong>

                <ul>
                  {result.errors.map(
                    (item, index) => (
                      <li key={index}>{item}</li>
                    ),
                  )}
                </ul>
              </div>
            </div>
          )}

          <div className="import-result-actions">
            <button
              type="button"
              className="primary-button"
              onClick={() => navigate("/prioritization")}
            >
              View Prioritization
            </button>

            <button
              type="button"
              className="secondary-button"
              onClick={() => navigate("/attack-paths")}
            >
              View Attack Graph
            </button>
          </div>
        </section>
      )}
    </div>
  );
}






