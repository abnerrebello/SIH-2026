import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  Database,
  Globe2,
  Layers3,
  LockKeyhole,
  Network,
  Search,
  Server,
  ShieldAlert,
  Target,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api, type Asset } from "./lib/api";

const criticalityLevels = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

function assetTypeLabel(value: string) {
  return value
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function assetIcon(type: string) {
  const normalized = type.toUpperCase();
  if (normalized.includes("DATABASE")) return <Database size={18} />;
  if (normalized.includes("GATEWAY") || normalized.includes("NETWORK")) return <Network size={18} />;
  if (normalized.includes("IDENTITY")) return <Target size={18} />;
  if (normalized.includes("ENDPOINT")) return <Layers3 size={18} />;
  return <Server size={18} />;
}

function criticalityClass(level: string) {
  return `asset-criticality asset-criticality-${level.toLowerCase()}`;
}

export default function AssetsPage() {
  const query = useQuery({
    queryKey: ["assets"],
    queryFn: api.assets,
    refetchInterval: 30000,
  });

  const [search, setSearch] = useState("");
  const [criticality, setCriticality] = useState("ALL");

  if (query.isLoading) {
    return (
      <div className="assets-state">
        <div className="assets-spinner" />
        <strong>Mapping the attack surface</strong>
        <span>Loading assets from the current security environment.</span>
      </div>
    );
  }

  if (query.error) {
    return (
      <div className="assets-state">
        <ShieldAlert size={28} />
        <strong>Asset inventory unavailable</strong>
        <span>Singularity could not load the current environment assets.</span>
      </div>
    );
  }

  const assets = query.data ?? [];

  const filteredAssets = assets.filter((asset) => {
    const queryText = search.trim().toLowerCase();
    const matchesSearch =
      !queryText ||
      [asset.name, asset.hostname, asset.ip_address ?? "", asset.asset_type, asset.operating_system ?? ""]
        .join(" ")
        .toLowerCase()
        .includes(queryText);
    return matchesSearch && (criticality === "ALL" || asset.criticality === criticality);
  });

  const counts = {
    total: assets.length,
    critical: assets.filter((asset) => asset.criticality === "CRITICAL").length,
    exposed: assets.filter((asset) => asset.internet_exposed).length,
    internal: assets.filter((asset) => !asset.internet_exposed).length,
    highValue: assets.filter(
      (asset) => asset.criticality === "CRITICAL" || asset.criticality === "HIGH",
    ).length,
  };

  return (
    <div className="assets-page">
      <div className="assets-field" aria-hidden="true">
        <div className="assets-grid" />
        <div className="assets-orbit assets-orbit-a" />
        <div className="assets-orbit assets-orbit-b" />
        <div className="assets-beam assets-beam-a" />
        <div className="assets-beam assets-beam-b" />
        <span className="assets-node assets-node-a" />
        <span className="assets-node assets-node-b" />
        <span className="assets-node assets-node-c" />
      </div>

      <section className="assets-hero">
        <div className="assets-hero-copy">
          <div className="assets-eyebrow">
            <Network size={15} />
            Attack Surface
          </div>
          <h2>
            Know every system
            <br />
            <span>that matters.</span>
          </h2>
          <p>
            A live inventory of the systems Singularity uses to understand
            exposure, criticality and the routes an attacker could take.
          </p>
        </div>

        <div className="assets-hero-summary">
          <div className="assets-hero-total">
            <strong>{counts.total}</strong>
            <span>assets in scope</span>
          </div>
          <div className="assets-hero-breakdown">
            <div><span>Critical</span><strong>{counts.critical}</strong></div>
            <div><span>Internet-facing</span><strong>{counts.exposed}</strong></div>
            <div><span>Internal</span><strong>{counts.internal}</strong></div>
          </div>
        </div>
      </section>

      <section className="assets-insight-strip">
        <div><span>ENVIRONMENT VIEW</span><strong>Asset inventory</strong></div>
        <div><span>EXTERNAL PERIMETER</span><strong>{counts.exposed}</strong><small>externally reachable</small></div>
        <div><span>HIGH-VALUE SYSTEMS</span><strong>{counts.highValue}</strong><small>high or critical</small></div>
        <div><span>VISIBILITY</span><strong>100%</strong><small>systems currently mapped</small></div>
      </section>

      <section className="assets-workspace">
        <div className="assets-toolbar">
          <div className="assets-toolbar-copy">
            <span>ASSET REGISTER</span>
            <h3>Current environment</h3>
            <p>Search the inventory or narrow it by business criticality.</p>
          </div>

          <div className="assets-controls">
            <label className="assets-search">
              <Search size={16} />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search assets, hosts or IPs"
              />
            </label>
            <div className="assets-filters">
              {criticalityLevels.map((level) => (
                <button
                  key={level}
                  type="button"
                  className={criticality === level ? "active" : ""}
                  onClick={() => setCriticality(level)}
                >
                  {level === "ALL" ? "All" : level}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="assets-results-bar">
          <span>Showing <strong>{filteredAssets.length}</strong> of <strong>{assets.length}</strong> assets</span>
          <span>{criticality === "ALL" ? "All criticality levels" : `${criticality.charAt(0)}${criticality.slice(1).toLowerCase()} assets`}</span>
        </div>

        <div className="assets-cards">
          {filteredAssets.map((asset) => <AssetCard asset={asset} key={asset.id} />)}
          {filteredAssets.length === 0 && (
            <div className="assets-empty">
              <Search size={22} />
              <strong>No matching assets</strong>
              <span>Try a broader search or reset the criticality filter.</span>
            </div>
          )}
        </div>
      </section>

      <div className="assets-footer-note">
        <span>Inventory refreshes automatically as the environment changes.</span>
        <Link to="/network">Open network map <ArrowRight size={14} /></Link>
      </div>
    </div>
  );
}

function AssetCard({ asset }: { asset: Asset }) {
  return (
    <article className={`asset-card asset-card-${asset.criticality.toLowerCase()}`}>
      <div className="asset-card-top">
        <div className="asset-card-icon">{assetIcon(asset.asset_type)}</div>
        <span className={criticalityClass(asset.criticality)}>{asset.criticality}</span>
      </div>

      <div className="asset-card-main">
        <span className="asset-card-type">{assetTypeLabel(asset.asset_type)}</span>
        <h3>{asset.name}</h3>
        <div className="asset-card-host">
          <span>{asset.hostname}</span>
          {asset.ip_address && <span>{asset.ip_address}</span>}
        </div>
      </div>

      <div className="asset-card-bottom">
        <div className="asset-card-meta">
          <span>Operating system</span>
          <strong>{asset.operating_system || "Not specified"}</strong>
        </div>
        <div className={`asset-exposure ${asset.internet_exposed ? "public" : "internal"}`}>
          {asset.internet_exposed ? (
            <><Globe2 size={14} /><span>Internet-facing</span></>
          ) : (
            <><LockKeyhole size={14} /><span>Internal</span></>
          )}
        </div>
      </div>
    </article>
  );
}

