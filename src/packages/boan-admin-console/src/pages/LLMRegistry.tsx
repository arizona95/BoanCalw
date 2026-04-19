import { useEffect, useState } from "react";
import { registryApi, credentialApi, type LLMEntry, type LLMRegistrationHistory, type RegisterLLMPayload } from "../api";

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
  const [history, setHistory] = useState<LLMRegistrationHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"register" | "bindings" | "history">("register");
  const [registerType, setRegisterType] = useState<"llm" | "image">("llm");
  const [name, setName] = useState("");
  const [curlTemplate, setCurlTemplate] = useState("");
  const [imageCurlTemplate, setImageCurlTemplate] = useState("");
  const [registering, setRegistering] = useState(false);
  const [showExample, setShowExample] = useState(false);
  const [storeDetectedCredentials, setStoreDetectedCredentials] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const currentCurl = registerType === "llm" ? curlTemplate : imageCurlTemplate;
  const detectedKeys = currentCurl ? detectKeys(currentCurl) : [];

  const load = () => {
    setLoading(true);
    Promise.all([registryApi.list(), registryApi.history()])
      .then(([entries, historyEntries]) => {
        setLlms(entries);
        setHistory(historyEntries);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleRegister = async () => {
    if (!name.trim()) { setError("모델 이름을 입력하세요."); return; }
    if (tab !== "register") { setError("등록 탭에서만 등록 가능합니다."); return; }
    const curl = currentCurl;
    if (!curl.trim()) { setError("curl 명령어를 입력하세요."); return; }
    if (!parseCurlEndpoint(curl)) { setError("curl에서 URL을 파싱할 수 없습니다."); return; }

    setError(null);
    setSuccess(null);
    setRegistering(true);

    try {
      const keys = detectKeys(curl);

      const payload: RegisterLLMPayload = {
        name: name.trim(),
        type: registerType,
        store_detected_credentials: storeDetectedCredentials,
        ...(registerType === "llm"
          ? { curl_template: curl }
          : { image_curl_template: curl }),
      };

      await registryApi.register(payload);

      const msg = keys.length > 0 && storeDetectedCredentials
        ? `등록 완료. 감지된 API 키 ${keys.length}개가 credential-filter에 암호화 저장되었습니다.`
        : keys.length > 0
        ? `등록 완료. 감지된 API 키 ${keys.length}개는 저장하지 않고 placeholder로만 치환했습니다.`
        : `등록 완료: ${name}`;
      setSuccess(msg);
      setName("");
      setCurlTemplate("");
      setImageCurlTemplate("");
      setStoreDetectedCredentials(false);
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

  const handleBindLMM = async (name: string) => {
    setError(null);
    try {
      await registryApi.bindSecurityLMM(name);
      setSuccess(`${name}을 Security LMM(Vision)으로 설정했습니다.`);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "바인딩 실패");
    }
  };

  const handleBindRole = async (name: string, role: "chat" | "g2" | "g3") => {
    setError(null);
    try {
      await registryApi.bindRole(name, role);
      setSuccess(`${name}을 ${role.toUpperCase()} 역할로 바인딩`);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "바인딩 실패");
    }
  };

  const handleUnbindRole = async (name: string, role: "chat" | "g2" | "g3") => {
    setError(null);
    try {
      await registryApi.unbindRole(name, role);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "해제 실패");
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

  const handleClearHistory = async () => {
    if (!confirm("전체 히스토리를 삭제하시겠습니까?")) return;
    setError(null);
    try {
      await registryApi.clearHistory();
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "삭제 실패");
    }
  };

  const handleDeleteHistoryItem = async (name: string, registeredAt: string) => {
    setError(null);
    try {
      await registryApi.deleteHistoryItem(name, registeredAt);
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

      <div className="flex gap-2 mb-5 border-b border-gray-200">
        {(["register", "bindings", "history"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
              tab === t
                ? "border-boan-600 text-boan-600"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            {t === "register" ? "📝 모델 등록" : t === "bindings" ? "🎯 역할 설정" : "🕘 History"}
          </button>
        ))}
      </div>

      {tab === "register" && (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold">모델 등록</h2>
            <div className="flex gap-1 text-xs">
              {(["llm", "image"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setRegisterType(t)}
                  className={`px-2 py-1 rounded ${registerType === t ? "bg-boan-600 text-white" : "bg-gray-100 text-gray-600"}`}
                >
                  {t === "llm" ? "텍스트 LLM" : "이미지 모델"}
                </button>
              ))}
            </div>
          </div>
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
              <span>예시: {registerType === "llm" ? "텍스트 LLM (Anthropic)" : "멀티모달 (Anthropic Vision)"}</span>
              <button
                onClick={() => {
                  const ex = registerType === "llm" ? EXAMPLE_LLM_CURL : EXAMPLE_IMAGE_CURL;
                  if (registerType === "llm") setCurlTemplate(ex); else setImageCurlTemplate(ex);
                }}
                className="text-boan-400 hover:text-boan-300"
              >
                ← 예시 적용
              </button>
            </div>
            <pre className="bg-gray-900 text-green-400 text-xs p-4 overflow-x-auto whitespace-pre">
              {registerType === "llm" ? EXAMPLE_LLM_CURL : EXAMPLE_IMAGE_CURL}
            </pre>
          </div>
        )}

        {detectedKeys.length > 0 && (
          <div className="mb-4 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            <div className="font-medium mb-1">Credential 감지됨</div>
            <p className="mb-3">
              이 curl에는 credential로 보이는 값이 {detectedKeys.length}개 있습니다. 저장을 선택하면
              <span className="font-medium text-boan-700"> Credentials</span>에 등록하고, 저장하지 않으면
              placeholder만 남깁니다.
            </p>
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={storeDetectedCredentials}
                onChange={(e) => setStoreDetectedCredentials(e.target.checked)}
                className="rounded border-gray-300 text-boan-600 focus:ring-boan-500"
              />
              <span>감지된 credential을 Credentials에 저장</span>
            </label>
          </div>
        )}

        <div className="flex flex-col gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">모델 이름</label>
            <input
              type="text"
              placeholder={registerType === "llm" ? "예: claude-3-5-sonnet" : "예: claude-3-vision"}
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
            />
          </div>

          {registerType === "llm" ? (
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
                {registerType === "image" && <span><code className="bg-white px-1 rounded border">{"{{IMAGE_BASE64}}"}</code> → base64 이미지 데이터</span>}
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

          {registerType === "image" && (
            <div className="rounded-lg border border-purple-200 bg-purple-50 p-4">
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">
                  <div className="text-xs font-medium text-purple-800 mb-2">테스트 이미지</div>
                  {/* 빨간 사각형 + "TEST" 글자 16x16 PNG */}
                  <img
                    src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAaElEQVR42u3RAQ0AAAjDMK5/aiDg40iLg6ZJk5SSDKAJgAEoAAYwAAVgAAvAAQwAA1AABjAAAxiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABTwLIQABBpiZ4QAAAABJRU5ErkJggg=="
                    alt="test pattern"
                    className="w-16 h-16 border-2 border-purple-300 rounded"
                  />
                  <div className="text-xs text-purple-600 mt-1 text-center">64×64</div>
                </div>
                <div className="flex-1 text-xs text-purple-800">
                  <p className="font-medium mb-1">이미지 모델 등록 시 자동 테스트</p>
                  <p className="text-purple-700">
                    등록 버튼을 누르면 위 테스트 이미지를 <code className="bg-white px-1 rounded">{"{{IMAGE_BASE64}}"}</code>에
                    치환해서 실제 호출합니다. 응답이 200이면 등록되고, 실패하면 정확한 오류를 표시합니다.
                  </p>
                  <p className="text-purple-600 mt-1">
                    curl에 <code className="bg-white px-1 rounded">{"{{IMAGE_BASE64}}"}</code> 플레이스홀더를 사용하세요.
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <button
              onClick={handleRegister}
              disabled={registering}
              className="px-6 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50"
            >
              {registering
                ? detectedKeys.length > 0 ? "키 저장 중..." : "등록 + 테스트 호출 중..."
                : `${registerType === "llm" ? "LLM" : "Image 모델"} 등록`}
            </button>
          </div>
        </div>
      </div>
      )}

      {tab === "history" && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          {loading ? (
            <p className="text-gray-500 text-sm">로딩 중...</p>
          ) : history.length === 0 ? (
            <p className="text-gray-400 text-sm">등록 성공 이력이 없습니다.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex justify-end">
                <button onClick={handleClearHistory} className="text-xs text-red-600 hover:underline">전체 삭제</button>
              </div>
              {history.map((item, idx) => {
                const curl = item.curl_template ?? item.image_curl_template ?? "";
                return (
                  <div key={`${item.name}-${item.registered_at}-${idx}`} className="rounded-lg border border-gray-200 bg-gray-50 p-4">
                    <div className="flex items-center justify-between gap-4 mb-2">
                      <div>
                        <div className="font-medium text-sm">{item.name}</div>
                        <div className="text-xs text-gray-500">{item.type === "image" ? "Image" : "LLM"} · {new Date(item.registered_at).toLocaleString()}</div>
                      </div>
                      <button onClick={() => handleDeleteHistoryItem(item.name, item.registered_at)} className="text-xs text-red-500 hover:underline">삭제</button>
                    </div>
                    <pre className="bg-white text-gray-700 text-xs p-3 rounded border border-gray-200 overflow-x-auto whitespace-pre-wrap break-all">{curl || "curl 템플릿 없음"}</pre>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {tab === "bindings" && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-4">
          {loading ? (
            <p className="p-6 text-gray-500 text-sm">로딩 중...</p>
          ) : llms.length === 0 ? (
            <p className="p-6 text-gray-400 text-sm">등록된 모델이 없습니다.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-4 py-3 font-medium text-gray-500">이름</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500">상태</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500">키</th>
                  <th className="text-center px-2 py-3 font-medium text-blue-600">CHAT</th>
                  <th className="text-center px-2 py-3 font-medium text-amber-600">G2</th>
                  <th className="text-center px-2 py-3 font-medium text-green-600">G3</th>
                  <th className="text-right px-4 py-3 font-medium text-gray-500">액션</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {llms.map((llm) => {
                  const hasCred = (llm.curl_template ?? llm.image_curl_template ?? "").includes("{{CREDENTIAL:");
                  // Tailwind JIT 가 dynamic class 를 못 잡으므로 static lookup 사용.
                  // 새 역할 추가 시 이 lookup 에 색상을 명시해야 bundle 에 포함됨.
                  const ROLE_BG: Record<string, string> = {
                    chat: "bg-blue-500",
                    g2: "bg-amber-500",
                    g3: "bg-green-500",
                  };
                  const RoleCell = ({ role }: { role: "chat" | "g2" | "g3" }) => {
                    const isBound = llm.roles?.includes(role) ?? false;
                    const boundClass = ROLE_BG[role] ?? "bg-gray-500";
                    return (
                      <td className="px-2 py-3 text-center">
                        <button
                          onClick={() => (isBound ? handleUnbindRole(llm.name, role) : handleBindRole(llm.name, role))}
                          className={`w-7 h-7 rounded-full text-xs font-bold transition-all ${
                            isBound ? `${boundClass} text-white shadow-md` : "bg-gray-100 text-gray-300 hover:bg-gray-200"
                          }`}
                          title={isBound ? `${role.toUpperCase()} 해제` : `${role.toUpperCase()} 바인딩`}
                        >
                          {isBound ? "✓" : "+"}
                        </button>
                      </td>
                    );
                  };
                  const typeIcon = llm.type === "image" ? "🖼️" : "💬";
                  return (
                    <tr key={llm.name} className="hover:bg-gray-50">
                      <td className="px-4 py-3 font-mono font-medium text-xs" title={llm.endpoint}>
                        <span className="mr-1">{typeIcon}</span>{llm.name}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-1 rounded-full ${llm.healthy ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"}`}>
                          {llm.healthy ? "healthy" : "unknown"}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {hasCred ? (
                          <span className="text-xs px-2 py-1 rounded-full bg-emerald-50 text-emerald-700">🔐</span>
                        ) : (
                          <span className="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-400">—</span>
                        )}
                      </td>
                      <RoleCell role="chat" />
                      <RoleCell role="g2" />
                      <RoleCell role="g3" />
                      <td className="px-4 py-3 text-right">
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
      )}
    </div>
  );
}
