import { useEffect, useState } from "react";
import { credentialApi, type Credential } from "../api";

const STATUS_STYLE: Record<string, string> = {
  ok: "bg-green-50 text-green-700",
  expired: "bg-red-50 text-red-700",
  missing: "bg-yellow-50 text-yellow-700",
};

export default function Credentials() {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    credentialApi
      .list()
      .then(setCreds)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleAdd = async () => {
    if (!name.trim() || !provider.trim()) return;
    setError(null);
    try {
      await credentialApi.add(name.trim(), provider.trim());
      setName("");
      setProvider("");
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Add failed");
    }
  };

  const handleRevoke = async (id: string) => {
    try {
      await credentialApi.revoke(id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Revoke failed");
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Credentials</h1>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
          {error}
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold mb-4">Add Credential</h2>
        <div className="flex gap-3">
          <input
            type="text"
            placeholder="Credential name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
          />
          <input
            type="text"
            placeholder="Provider (e.g. openai, anthropic)"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
          />
          <button
            onClick={handleAdd}
            className="px-4 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700"
          >
            Add
          </button>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <p className="p-6 text-gray-500">Loading...</p>
        ) : creds.length === 0 ? (
          <p className="p-6 text-gray-500">No credentials configured.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Name</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Provider</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Status</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Expires</th>
                <th className="text-right px-6 py-3 font-medium text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {creds.map((c) => (
                <tr key={c.id} className="hover:bg-gray-50">
                  <td className="px-6 py-3 font-mono">{c.name}</td>
                  <td className="px-6 py-3 text-gray-600">{c.provider}</td>
                  <td className="px-6 py-3">
                    <span
                      className={`text-xs px-2 py-1 rounded-full ${
                        STATUS_STYLE[c.status] || STATUS_STYLE.ok
                      }`}
                    >
                      {c.status}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-gray-500">{c.expires_at}</td>
                  <td className="px-6 py-3 text-right">
                    <button
                      onClick={() => handleRevoke(c.id)}
                      className="text-xs text-red-600 hover:underline"
                    >
                      revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
