import { useEffect, useState } from "react";
import { policyApi, type OrgPolicy } from "../api";

export default function Policies() {
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [editJson, setEditJson] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    policyApi
      .get()
      .then((p) => {
        setPolicy(p);
        setEditJson(JSON.stringify(p.rules, null, 2));
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleSave = async () => {
    setError(null);
    setSuccess(null);
    try {
      const parsed = JSON.parse(editJson);
      setSaving(true);
      const updated = await policyApi.update(parsed);
      setPolicy(updated);
      setSuccess("Policy updated successfully");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Invalid JSON");
    } finally {
      setSaving(false);
    }
  };

  const handleRollback = async () => {
    setError(null);
    setSuccess(null);
    try {
      setSaving(true);
      const rolled = await policyApi.rollback();
      setPolicy(rolled);
      setEditJson(JSON.stringify(rolled.rules, null, 2));
      setSuccess("Rolled back to previous version");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Rollback failed");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Organization Policy</h1>
          {policy && (
            <p className="text-sm text-gray-500 mt-1">
              Version {policy.version} &middot; Org: {policy.org_id} &middot;
              Updated: {policy.updated_at}
            </p>
          )}
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleRollback}
            disabled={saving}
            className="px-4 py-2 text-sm rounded-lg border border-gray-300 hover:bg-gray-100 disabled:opacity-50"
          >
            Rollback
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Policy"}
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 p-3 rounded-lg bg-green-50 text-green-700 text-sm">
          {success}
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <textarea
          value={editJson}
          onChange={(e) => setEditJson(e.target.value)}
          className="w-full h-[600px] p-4 font-mono text-sm resize-none focus:outline-none"
          spellCheck={false}
        />
      </div>
    </div>
  );
}
