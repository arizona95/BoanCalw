import { useEffect, useState } from "react";
import { registryApi, credentialApi, type LLMEntry, type RegisterLLMPayload } from "../api";

const EXAMPLE_LLM_CURL = `curl -X POST https://api.anthropic.com/v1/messages \\
  -H "x-api-key: sk-ant-api03-YOUR_KEY_HERE" \\
  -H "anthropic-version: 2023-06-01" \\
  -H "content-type: application/json" \\
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "{{MESSAGE}}"}]
  }'`;

const EXAMPLE_IMAGE_CURL = `curl -X POST https://api.anthropic.com/v1/messages \\
  -H "x-api-key: sk-ant-api03-YOUR_KEY_HERE" \\
  -H "anthropic-version: 2023-06-01" \\
  -H "content-type: application/json" \\
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [{
      "role": "user",
      "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "{{IMAGE_BASE64}}"}},
        {"type": "text", "text": "{{MESSAGE}}"}
      ]
    }]
  }'`;

interface DetectedKey {
  original: string;
  pattern: string;
  headerName: string;
}

const KEY_PATTERNS: { re: RegExp; header: string; label: string }[] = [
  { re: /-H\s+["']?(Authorization|authorization):\s*Bearer\s+([A-Za-z0-9\-_\.=]{16,})["']?/g,  header: "Authorization", label: "Bearer Token" },
  { re: /-H\s+["']?(x-api-key|X-Api-Key|x-goog-api-key):\s*([A-Za-z0-9\-_\.=]{16,})["']?/g,   header: "x-api-key",       label: "API Key" },
  { re: /-H\s+["']?(api-key|Api-Key):\s*([A-Za-z0-9\-_\.=]{16,})["']?/g,                        header: "api-key",         label: "API Key" },
];

function detectKeys(curl: string): DetectedKey[] {
  const found: DetectedKey[] = [];
  for (const { re, header } of KEY_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(curl)) !== null) {
      const key = m[2];
      if (!found.some((f) => f.original === key)) {
        found.push({ original: key, pattern: m[0], headerName: header });
      }
    }
  }
  return found;
}

function sanitizeCurl(curl: string, modelName: string): string {
  let out = curl;
  for (const { re } of KEY_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, (full, headerKey) => {
      return full.replace(/:\s*[A-Za-z0-9\-_\.=]{16,}/, `: {{CREDENTIAL:${modelName}}}`);
      void headerKey;
    });
  }
  return out;
}

function parseCurlEndpoint(curl: string): string {
  for (const part of curl.split(/\s+/)) {
    const clean = part.replace(/['"\\]/g, "");
    if (clean.startsWith("http://") || clean.startsWith("https://")) return clean;
  }
  return "";
}

function maskKey(k: string) {
  if (k.length <= 8) return "****";
  return k.slice(0, 6) + "..." + k.slice(-4);
}

function CurlInput({
  value,
  onChange,
  placeholder,
  label,
  detectedKeys,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  label: string;
  detectedKeys: DetectedKey[];
}) {
  const endpoint = parseCurlEndpoint(value);
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={9}
        spellCheck={false}
        placeholder={placeholder}
        className="w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono focus:outline-none focus:ring-2 focus:ring-boan-500 resize-y bg-gray-50"
      />
      <div className="mt-1 flex flex-wrap gap-2 text-xs">
        {endpoint && (
          <span className="text-green-700 font-mono">✓ 엔드포인트: {endpoint}</span>
        )}
        {value && !endpoint && (
          <span className="text-red-600">URL을 찾을 수 없습니다.</span>
        )}
        {detectedKeys.map((k) => (
          <span key={k.original} className="flex items-center gap-1 px-2 py-0.5 bg-yellow-50 border border-yellow-300 rounded text-yellow-800">
            <span>🔑</span>
            <span className="font-mono">{k.headerName}: {maskKey(k.original)}</span>
            <span className="text-yellow-600">— 감지됨, 자동 암호화 저장됩니다</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function LLMRegistry() {
  const [llms, setLlms] = useState<LLMEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"llm" | "image">("llm");
  const [name, setName] = useState("");
  const [curlTemplate, setCurlTemplate] = useState("");
  const [imageCurlTemplate, setImageCurlTemplate] = useState("");
  const [registering, setRegistering] = useState(false);
  const [showExample, setShowExample] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const currentCurl = tab === "llm" ? curlTemplate : imageCurlTemplate;
  const detectedKeys = currentCurl ? detectKeys(currentCurl) : [];

  const load = () => {
    setLoading(true);
    registryApi.list()
      .then(setLlms)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleRegister = async () => {
    if (!name.trim()) { setError("모델 이름을 입력하세요."); return; }
    const curl = currentCurl;
    if (!curl.trim()) { setError("curl 명령어를 입력하세요."); return; }
    if (!parseCurlEndpoint(curl)) { setError("curl에서 URL을 파싱할 수 없습니다."); return; }

    setError(null);
    setSuccess(null);
    setRegistering(true);

    try {
      const keys = detectKeys(curl);
      for (const k of keys) {
        const role = `${name.trim()}-apikey`;
        await credentialApi.storeForLLM(role, k.original);
      }

      const safeCurl = keys.length > 0 ? sanitizeCurl(curl, name.trim()) : curl;

      const payload: RegisterLLMPayload = {
        name: name.trim(),
        type: tab,
        ...(tab === "llm"
          ? { curl_template: safeCurl }
          : { image_curl_template: safeCurl }),
      };

      await registryApi.register(payload);

      const msg = keys.length > 0
        ? `등록 완료. API 키 ${keys.length}개가 credential-filter에 암호화 저장되었습니다.`
        : `등록 완료: ${name}`;
      setSuccess(msg);
      setName("");
      setCurlTemplate("");
      setImageCurlTemplate("");
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "등록 실패");
    } finally {
      setRegistering(false);
    }
  };

  const handleBind = async (name: string) => {
    setError(null);
    try {
      await registryApi.bindSecurity(name);
      setSuccess(`${name}을 Security LLM으로 설정했습니다.`);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "바인딩 실패");
    }
  };

  const handleRemove = async (name: string) => {
    setError(null);
    try {
      await registryApi.remove(name);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "삭제 실패");
    }
  };

  const llmList = llms.filter((l) => l.type !== "image");
  const imageList = llms.filter((l) => l.type === "image");

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">LLM Registry</h1>
      <p className="text-sm text-gray-500 mb-6">
        curl 명령어를 그대로 붙여넣으면 API 키는 자동으로 감지되어{" "}
        <span className="font-medium text-boan-700">boan-credential-filter</span>에 암호화 저장됩니다.
      </p>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{error}</div>
      )}
      {success && (
        <div className="mb-4 p-3 rounded-lg bg-green-50 text-green-700 text-sm">{success}</div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">모델 등록</h2>
          <button
            onClick={() => setShowExample(!showExample)}
            className="text-xs text-boan-600 hover:underline"
          >
            {showExample ? "예시 닫기" : "curl 예시 보기"}
          </button>
        </div>

        {showExample && (
          <div className="mb-4 rounded-lg overflow-hidden border border-gray-700">
            <div className="flex items-center justify-between px-4 py-2 bg-gray-800 text-xs text-gray-400">
              <span>예시: {tab === "llm" ? "텍스트 LLM (Anthropic)" : "멀티모달 (Anthropic Vision)"}</span>
              <button
                onClick={() => {
                  const ex = tab === "llm" ? EXAMPLE_LLM_CURL : EXAMPLE_IMAGE_CURL;
                  if (tab === "llm") setCurlTemplate(ex); else setImageCurlTemplate(ex);
                }}
                className="text-boan-400 hover:text-boan-300"
              >
                ← 예시 적용
              </button>
            </div>
            <pre className="bg-gray-900 text-green-400 text-xs p-4 overflow-x-auto whitespace-pre">
              {tab === "llm" ? EXAMPLE_LLM_CURL : EXAMPLE_IMAGE_CURL}
            </pre>
          </div>
        )}

        <div className="flex gap-2 mb-5 border-b border-gray-200">
          {(["llm", "image"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
                tab === t
                  ? "border-boan-600 text-boan-600"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              {t === "llm" ? "💬 LLM (텍스트)" : "🖼️ Image (멀티모달)"}
            </button>
          ))}
        </div>

        <div className="flex flex-col gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">모델 이름</label>
            <input
              type="text"
              placeholder={tab === "llm" ? "예: claude-3-5-sonnet" : "예: claude-3-vision"}
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
            />
          </div>

          {tab === "llm" ? (
            <CurlInput
              value={curlTemplate}
              onChange={setCurlTemplate}
              label="curl 명령어 — {{MESSAGE}} 플레이스홀더, API 키 자동 추출"
              placeholder={EXAMPLE_LLM_CURL}
              detectedKeys={detectedKeys}
            />
          ) : (
            <CurlInput
              value={imageCurlTemplate}
              onChange={setImageCurlTemplate}
              label="curl 명령어 — {{MESSAGE}}, {{IMAGE_BASE64}} 플레이스홀더, API 키 자동 추출"
              placeholder={EXAMPLE_IMAGE_CURL}
              detectedKeys={detectedKeys}
            />
          )}

          <div className="flex items-start gap-2 text-xs text-gray-500 bg-gray-50 rounded-lg p-3">
            <div className="flex-1">
              <p className="font-medium mb-1">플레이스홀더 규칙</p>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                <span><code className="bg-white px-1 rounded border">{"{{MESSAGE}}"}</code> → 사용자 입력 텍스트</span>
                {tab === "image" && <span><code className="bg-white px-1 rounded border">{"{{IMAGE_BASE64}}"}</code> → base64 이미지 데이터</span>}
                <span><code className="bg-white px-1 rounded border">{"{{CREDENTIAL:이름}}"}</code> → 저장된 API 키 (자동 치환)</span>
              </div>
            </div>
          </div>

          {detectedKeys.length > 0 && (
            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 text-sm">
              <p className="font-medium text-yellow-800 mb-1">🔐 API 키 {detectedKeys.length}개 감지됨</p>
              <ul className="text-yellow-700 text-xs space-y-1">
                {detectedKeys.map((k) => (
                  <li key={k.original} className="font-mono">
                    {k.headerName}: {maskKey(k.original)}
                    <span className="text-yellow-600 ml-2">→ credential-filter에 암호화 저장 후 curl에서 제거됩니다</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex justify-end">
            <button
              onClick={handleRegister}
              disabled={registering}
              className="px-6 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50"
            >
              {registering
                ? detectedKeys.length > 0 ? "키 저장 중..." : "등록 중..."
                : `${tab === "llm" ? "LLM" : "Image 모델"} 등록`}
            </button>
          </div>
        </div>
      </div>

      {[
        { label: "💬 LLM (텍스트)", list: llmList },
        { label: "🖼️ Image (멀티모달)", list: imageList },
      ].map(({ label, list }) => (
        <div key={label} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-4">
          <div className="px-6 py-3 bg-gray-50 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-700">{label}</h3>
          </div>
          {loading ? (
            <p className="p-6 text-gray-500 text-sm">로딩 중...</p>
          ) : list.length === 0 ? (
            <p className="p-6 text-gray-400 text-sm">등록된 모델이 없습니다.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-6 py-3 font-medium text-gray-500">이름</th>
                  <th className="text-left px-6 py-3 font-medium text-gray-500">엔드포인트</th>
                  <th className="text-left px-6 py-3 font-medium text-gray-500">상태</th>
                  <th className="text-left px-6 py-3 font-medium text-gray-500">키 저장</th>
                  <th className="text-left px-6 py-3 font-medium text-gray-500">Security LLM</th>
                  <th className="text-right px-6 py-3 font-medium text-gray-500">액션</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {list.map((llm) => {
                  const hasCred = (llm.curl_template ?? llm.image_curl_template ?? "").includes("{{CREDENTIAL:");
                  return (
                    <tr key={llm.name} className="hover:bg-gray-50">
                      <td className="px-6 py-3 font-mono font-medium">{llm.name}</td>
                      <td className="px-6 py-3 text-gray-500 font-mono text-xs max-w-xs truncate">
                        {llm.endpoint || "—"}
                      </td>
                      <td className="px-6 py-3">
                        <span className={`text-xs px-2 py-1 rounded-full ${llm.healthy ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"}`}>
                          {llm.healthy ? "healthy" : "unknown"}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        {hasCred ? (
                          <span className="text-xs px-2 py-1 rounded-full bg-emerald-50 text-emerald-700">🔐 저장됨</span>
                        ) : (
                          <span className="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-400">키 없음</span>
                        )}
                      </td>
                      <td className="px-6 py-3">
                        {llm.is_security_llm ? (
                          <span className="text-xs px-2 py-1 rounded-full bg-blue-50 text-blue-700">✓ 보안 LLM</span>
                        ) : (
                          <button
                            onClick={() => handleBind(llm.name)}
                            className="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600 hover:bg-blue-50 hover:text-blue-700"
                          >
                            bind
                          </button>
                        )}
                      </td>
                      <td className="px-6 py-3 text-right">
                        <button
                          onClick={() => handleRemove(llm.name)}
                          className="text-xs text-red-600 hover:underline"
                        >
                          삭제
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </div>
  );
}
