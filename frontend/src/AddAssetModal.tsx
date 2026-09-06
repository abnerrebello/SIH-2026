import { useEffect, useState, type FormEvent } from "react";
import { PackageSearch, X } from "lucide-react";
import { api, type Asset } from "./lib/api";

export default function AddAssetModal() {
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    name: "",
    hostname: "",
    ip_address: "",
    asset_type: "SERVER",
    operating_system: "",
    criticality: "MEDIUM",
    internet_exposed: false,
    description: "",
    connectTo: "",
    direction: "new-to-existing",
    relationship_type: "NETWORK_ACCESS",
    trust_level: "MEDIUM",
  });

  const update = (key: string, value: string | boolean) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  useEffect(() => {
    if (!open) return;

    setLoadingAssets(true);

    api.assets()
      .then(setAssets)
      .catch(() => setAssets([]))
      .finally(() => setLoadingAssets(false));
  }, [open]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");

    if (!form.name.trim()) {
      setError("Asset name is required.");
      return;
    }

    setSaving(true);

    try {
      const created = await api.createAsset({
        name: form.name.trim(),
        hostname: form.hostname.trim() || undefined,
        ip_address: form.ip_address.trim() || undefined,
        asset_type: form.asset_type,
        operating_system: form.operating_system.trim() || undefined,
        criticality: form.criticality as
          | "LOW"
          | "MEDIUM"
          | "HIGH"
          | "CRITICAL",
        internet_exposed: form.internet_exposed,
        description: form.description.trim() || undefined,
      });

      if (form.connectTo) {
        const existingId = Number(form.connectTo);

        await api.createNetworkRelationship(
          form.direction === "new-to-existing"
            ? {
                source_asset_id: created.id,
                target_asset_id: existingId,
                relationship_type: form.relationship_type,
                trust_level: form.trust_level,
              }
            : {
                source_asset_id: existingId,
                target_asset_id: created.id,
                relationship_type: form.relationship_type,
                trust_level: form.trust_level,
              },
        );
      }

      setOpen(false);
      window.location.reload();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to create the asset.",
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <button
        type="button"
        className="primary-button"
        onClick={() => {
          setError("");
          setOpen(true);
        }}
      >
        <PackageSearch size={16} />
        Add asset
      </button>

      {open && (
        <div
          className="asset-modal-backdrop"
          onMouseDown={() => setOpen(false)}
        >
          <div
            className="asset-modal"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="asset-modal-header">
              <div>
                <div className="eyebrow">NEW ASSET</div>
                <h2>Add asset</h2>
              </div>

              <button
                type="button"
                className="icon-button"
                onClick={() => setOpen(false)}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={submit} className="asset-form">
              <div className="asset-form-grid">
                <label>
                  Name *
                  <input
                    value={form.name}
                    onChange={(e) => update("name", e.target.value)}
                    placeholder="Production Web Server"
                  />
                </label>

                <label>
                  Hostname
                  <input
                    value={form.hostname}
                    onChange={(e) =>
                      update("hostname", e.target.value)
                    }
                    placeholder="web-prod-01"
                  />
                </label>

                <label>
                  IP address
                  <input
                    value={form.ip_address}
                    onChange={(e) =>
                      update("ip_address", e.target.value)
                    }
                    placeholder="10.0.0.25"
                  />
                </label>

                <label>
                  Asset type
                  <select
                    value={form.asset_type}
                    onChange={(e) =>
                      update("asset_type", e.target.value)
                    }
                  >
                    <option value="SERVER">Server</option>
                    <option value="WORKSTATION">Workstation</option>
                    <option value="DATABASE">Database</option>
                    <option value="APPLICATION">Application</option>
                    <option value="NETWORK_DEVICE">Network Device</option>
                    <option value="CLOUD">Cloud</option>
                  </select>
                </label>

                <label>
                  Operating system
                  <input
                    value={form.operating_system}
                    onChange={(e) =>
                      update("operating_system", e.target.value)
                    }
                    placeholder="Windows Server 2022"
                  />
                </label>

                <label>
                  Criticality
                  <select
                    value={form.criticality}
                    onChange={(e) =>
                      update("criticality", e.target.value)
                    }
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </label>
              </div>

              <div className="asset-connection-section">
                <div className="asset-connection-heading">
                  <strong>Network connection</strong>
                  <span>
                    Add a relationship so the asset becomes part of the
                    attack graph.
                  </span>
                </div>

                <div className="asset-form-grid">
                  <label>
                    Existing asset
                    <select
                      value={form.connectTo}
                      onChange={(e) =>
                        update("connectTo", e.target.value)
                      }
                    >
                      <option value="">
                        {loadingAssets
                          ? "Loading assets..."
                          : "No connection"}
                      </option>

                      {assets.map((asset) => (
                        <option
                          key={asset.id}
                          value={String(asset.id)}
                        >
                          {asset.name}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label>
                    Flow direction
                    <select
                      value={form.direction}
                      onChange={(e) =>
                        update("direction", e.target.value)
                      }
                    >
                      <option value="new-to-existing">
                        New asset to existing asset
                      </option>
                      <option value="existing-to-new">
                        Existing asset to new asset
                      </option>
                    </select>
                  </label>

                  <label>
                    Relationship
                    <select
                      value={form.relationship_type}
                      onChange={(e) =>
                        update("relationship_type", e.target.value)
                      }
                    >
                      <option value="NETWORK_ACCESS">
                        Network access
                      </option>
                      <option value="LATERAL_MOVEMENT">
                        Lateral movement
                      </option>
                      <option value="APPLICATION_ACCESS">
                        Application access
                      </option>
                      <option value="DATABASE_ACCESS">
                        Database access
                      </option>
                      <option value="IDENTITY_ACCESS">
                        Identity access
                      </option>
                    </select>
                  </label>

                  <label>
                    Connection trust
                    <select
                      value={form.trust_level}
                      onChange={(e) =>
                        update("trust_level", e.target.value)
                      }
                    >
                      <option value="LOW">
                        Low - stronger trust
                      </option>
                      <option value="MEDIUM">
                        Medium - moderate trust
                      </option>
                      <option value="HIGH">
                        High - weaker trust boundary
                      </option>
                    </select>
                  </label>
                </div>
              </div>

              <label>
                Description
                <textarea
                  value={form.description}
                  onChange={(e) =>
                    update("description", e.target.value)
                  }
                  placeholder="What this asset is used for..."
                  rows={3}
                />
              </label>

              <label className="asset-checkbox">
                <input
                  type="checkbox"
                  checked={form.internet_exposed}
                  onChange={(e) =>
                    update("internet_exposed", e.target.checked)
                  }
                />
                Internet exposed
              </label>

              {error && (
                <div className="form-error">{error}</div>
              )}

              <div className="asset-modal-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setOpen(false)}
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="primary-button"
                  disabled={saving}
                >
                  {saving ? "Creating..." : "Create asset"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
