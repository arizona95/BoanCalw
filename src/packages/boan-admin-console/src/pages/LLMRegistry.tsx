import { useEffect, useState } from "react";
import { registryApi, type LLMEntry } from "../api";

export default function LLMRegistry() {
  const [llms, setLlms] = useState<LLMEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    registryApi
      .list()
      .then(setLlms)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleRegister = async () => {
    if (!name.trim() || !endpoint.trim()) return;
    setError(null);
    try {
      await registryApi.register(name.trim(), endpoint.trim());
      setName("");
      setEndpoint("");
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Registration failed");
    }
  };

  const handleBind = async (id: string) => {
    try {
      await registryApi.bindSecurity(id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Bind failed");
    }
  };

  const handleRemove = async (id: string) => {
    try {
      await registryApi.remove(id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Remove failed");
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">LLM Registry</h1>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
          {error}
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold mb-4">Register New LLM</h2>
        <div className="flex gap-3">
          <input
            type="text"
            placeholder="Name (e.g. gpt-4o)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
          />
          <input
            type="text"
            placeholder="Endpoint URL"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
          />
          <button
            onClick={handleRegister}
            className="px-4 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700"
          >
            Register
          </button>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <p className="p-6 text-gray-500">Loading...</p>
        ) : llms.length === 0 ? (
          <p className="p-6 text-gray-500">No LLMs registered yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Name</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Endpoint</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Security LLM</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Created</th>
                <th className="text-right px-6 py-3 font-medium text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {llms.map((llm) => (
                <tr key={llm.id} className="hover:bg-gray-50">
                  <td className="px-6 py-3 font-mono">{llm.name}</td>
                  <td className="px-6 py-3 text-gray-600 font-mono text-xs">{llm.endpoint}</td>
                  <td className="px-6 py-3">
                    {llm.is_security_llm ? (
                      <span className="text-xs px-2 py-1 rounded-full bg-blue-50 text-blue-700">bound</span>
                    ) : (
                      <button
                        onClick={() => handleBind(llm.id)}
                        className="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600 hover:bg-blue-50 hover:text-blue-700"
                      >
                        bind
                      </button>
                    )}
                  </td>
                  <td className="px-6 py-3 text-gray-500">{llm.created_at}</td>
                  <td className="px-6 py-3 text-right">
                    <button
                      onClick={() => handleRemove(llm.id)}
                      className="text-xs text-red-600 hover:underline"
                    >
                      remove
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
