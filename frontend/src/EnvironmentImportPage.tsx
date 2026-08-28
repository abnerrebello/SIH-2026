import {
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
} from "react";
import { useNavigate } from "react-router-dom";
import {
  CheckCircle2,
  FileText,
  Upload,
  Download,
  AlertTriangle,
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

export default function EnvironmentImportPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState("");

  const selectFile = (selected: File | null) => {
    if (!selected) return;

    setResult(null);
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

    try {
      const data = await api.importEnvironment(file);
      setResult(data as ImportResult);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Environment import failed.",
      );
    } finally {
      setLoading(false);
    }
  };

  const downloadTemplate = () => {
    const csv = [
      "record_type,name,hostname,ip_address,asset_type,operating_system,criticality,internet_exposed,cve_id,title,description,cvss_score,severity,exploitability_score,actively_exploited,known_exploit,source_asset,target_asset,relationship_type,trust_level,asset_name,status",
      "ASSET,Web Server,web.example.com,10.0.0.10,WEB_SERVER,Linux,HIGH,true",
      "ASSET,Application Server,app.example.com,10.0.0.20,APPLICATION_SERVER,Linux,HIGH,false",
      "ASSET,Production Database,db.example.com,10.0.0.30,DATABASE,PostgreSQL,CRITICAL,false",
      "VULNERABILITY,,,,,,,,CVE-2024-3094,XZ Utils Backdoor,,10.0,CRITICAL,3.9,true,true",
      "RELATIONSHIP,,,,,,,,,,,,,,,,Web Server,Application Server,NETWORK_ACCESS,LOW",
      "RELATIONSHIP,,,,,,,,,,,,,,,,Application Server,Production Database,DATABASE_ACCESS,HIGH",
      "MAPPING,Web Server,,,,,,,CVE-2024-3094",
    ].join("\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "singularity-environment-template.csv";
    link.click();

    URL.revokeObjectURL(url);
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
                Import assets, vulnerabilities, relationships,
                and vulnerability mappings from CSV.
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
                  {(file.size / 1024).toFixed(1)} KB · CSV
                </div>

                <button
                  type="button"
                  className="text-button"
                  onClick={(event) => {
                    event.stopPropagation();
                    setFile(null);
                    setResult(null);
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

                <h3>
                  Drop your CSV here
                </h3>

                <p>
                  or click to browse your computer
                </p>

                <span className="import-helper">
                  CSV only · maximum 5 MB
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
                : "Import Environment"}
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
                Risk and attack-path analysis uses the
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
              <div className="eyebrow">IMPORT COMPLETE</div>
              <h2>{result.filename}</h2>
              <p>
                Your environment data has been imported
                successfully.
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
              onClick={() => navigate("/")}
            >
              View Security Dashboard
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
