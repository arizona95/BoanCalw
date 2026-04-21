// G3 Folder Wiki — 각 노드=skill, 폴더 트리로 계층화.
// LLM 이 agentic loop 로 read/write 하며 자기 memory 를 편집.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  wikiGraphApi,
  type WikiNode,
  type WikiDecision,
  type ClarificationDialog,
  type DialogTurn,
} from "../api";

type Tab = "folders" | "raw" | "dialog";

// ── 폴더 트리 빌더 ────────────────────────────────────────
type TreeNode = {
  name: string;        // segment 이름 (e.g. "security")
  fullPath: string;    // "/security"
  children: TreeNode[];
  skills: WikiNode[];  // 이 폴더 아래에 있는 leaf skill 노드들
};

function normalizePath(p?: string): string {
  if (!p || p === "/") return "/";
  const trimmed = p.replace(/\/+$/, "");
  return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
}

function buildTree(nodes: WikiNode[]): TreeNode {
  const root: TreeNode = { name: "/", fullPath: "/", children: [], skills: [] };
  const ensure = (path: string): TreeNode => {
    if (path === "/") return root;
    const segs = path.split("/").filter(Boolean);
    let cur = root;
    let cumulative = "";
    for (const seg of segs) {
      cumulative += "/" + seg;
      let child = cur.children.find((c) => c.name === seg);
      if (!child) {
        child = { name: seg, fullPath: cumulative, children: [], skills: [] };
        cur.children.push(child);
      }
      cur = child;
    }
    return cur;
  };
  for (const n of nodes) {
    const folder = ensure(normalizePath(n.path));
    folder.skills.push(n);
  }
  // 정렬
  const sortTree = (t: TreeNode) => {
    t.children.sort((a, b) => a.name.localeCompare(b.name));
    t.skills.sort((a, b) => a.definition.localeCompare(b.definition));
    t.children.forEach(sortTree);
  };
  sortTree(root);
  return root;
}

function FolderTree({
  tree,
  selectedId,
  selectedPath,
  onPickNode,
  onPickFolder,
  depth = 0,
}: {
  tree: TreeNode;
  selectedId: string | null;
  selectedPath: string;
  onPickNode: (id: string) => void;
  onPickFolder: (path: string) => void;
  depth?: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const isRoot = tree.fullPath === "/";
  const label = isRoot ? "/" : tree.name;
  const childCount = tree.children.length + tree.skills.length;
  return (
    <div>
      {!isRoot && (
        <button
          onClick={() => { setOpen(!open); onPickFolder(tree.fullPath); }}
          className={`w-full text-left px-2 py-1 rounded text-xs flex items-center gap-1 hover:bg-gray-100 ${
            selectedPath === tree.fullPath ? "bg-boan-50 text-boan-800 font-medium" : "text-gray-700"
          }`}
          style={{ paddingLeft: 8 + depth * 12 }}
        >
          <span className="w-3 text-[10px] text-gray-400">{open ? "▼" : "▶"}</span>
          <span>📂</span>
          <span className="flex-1 truncate">{label}</span>
          <span className="text-[10px] text-gray-400">{childCount}</span>
        </button>
      )}
      {isRoot && (
        <button
          onClick={() => onPickFolder("/")}
          className={`w-full text-left px-2 py-1 rounded text-xs flex items-center gap-1 hover:bg-gray-100 ${
            selectedPath === "/" ? "bg-boan-50 text-boan-800 font-medium" : "text-gray-700"
          }`}
        >
          <span className="w-3" />
          <span>📁</span>
          <span className="flex-1">/ (루트)</span>
          <span className="text-[10px] text-gray-400">{tree.skills.length}</span>
        </button>
      )}
      {open && (
        <>
          {tree.skills.map((s) => (
            <button
              key={s.id}
              onClick={() => onPickNode(s.id)}
              className={`w-full text-left px-2 py-1 rounded text-xs flex items-center gap-1 hover:bg-gray-100 ${
                selectedId === s.id ? "bg-boan-100 text-boan-900 font-medium" : "text-gray-600"
              }`}
              style={{ paddingLeft: 8 + (depth + 1) * 12 }}
              title={s.definition}
            >
              <span className="w-3" />
              <span>📄</span>
              <span className="flex-1 truncate">{s.definition || "(제목 없음)"}</span>
            </button>
          ))}
          {tree.children.map((c) => (
            <FolderTree
              key={c.fullPath}
              tree={c}
              selectedId={selectedId}
              selectedPath={selectedPath}
              onPickNode={onPickNode}
              onPickFolder={onPickFolder}
              depth={depth + 1}
            />
          ))}
        </>
      )}
    </div>
  );
}

// ── Skill 편집 패널 ──────────────────────────────────────
function SkillEditor({
  node,
  onSaved,
  onDeleted,
}: {
  node: WikiNode;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  const [definition, setDefinition] = useState(node.definition);
  const [content, setContent] = useState(node.content);
  const [path, setPath] = useState(node.path ?? "/");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setDefinition(node.definition);
    setContent(node.content);
    setPath(node.path ?? "/");
    setErr(null);
  }, [node.id]);

  const save = async () => {
    setSaving(true);
    setErr(null);
    try {
      await wikiGraphApi.updateNode(node.id, {
        definition,
        content,
        path: normalizePath(path),
        updated_by: "human",
      });
      onSaved();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const del = async () => {
    if (!confirm(`"${node.definition}" skill 삭제?`)) return;
    try {
      await wikiGraphApi.deleteNode(node.id);
      onDeleted();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 p-4 gap-3 overflow-y-auto">
      <div className="flex items-center gap-2 text-[10px] text-gray-400">
        <span className="font-mono">{node.id}</span>
        {node.created_by && <span>· {node.created_by}</span>}
        {node.updated_at && <span>· 수정 {new Date(node.updated_at).toLocaleString("ko-KR")}</span>}
      </div>
      <label className="text-xs text-gray-600">
        폴더 경로
        <input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="/security/credentials"
          className="mt-1 w-full text-xs font-mono border border-gray-300 rounded px-2 py-1"
        />
      </label>
      <label className="text-xs text-gray-600">
        Skill 제목 (≤30자)
        <input
          value={definition}
          maxLength={30}
          onChange={(e) => setDefinition(e.target.value)}
          className="mt-1 w-full text-sm font-semibold border border-gray-300 rounded px-2 py-1"
        />
      </label>
      <label className="text-xs text-gray-600 flex-1 flex flex-col">
        Skill 본문 (≤1000자) — [[node_id|이유]] 로 인라인 링크
        <textarea
          value={content}
          maxLength={1000}
          onChange={(e) => setContent(e.target.value)}
          className="mt-1 flex-1 min-h-[200px] text-xs font-mono border border-gray-300 rounded px-2 py-2 leading-relaxed"
        />
        <span className="text-[10px] text-gray-400 mt-1 self-end">{content.length}/1000</span>
      </label>
      {err && <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-2 py-1">{err}</div>}
      <div className="flex gap-2">
        <button
          onClick={save}
          disabled={saving}
          className="text-xs px-4 py-1.5 bg-boan-600 text-white rounded hover:bg-boan-700 disabled:opacity-40"
        >
          {saving ? "저장 중..." : "💾 저장"}
        </button>
        <button
          onClick={del}
          className="text-xs px-4 py-1.5 border border-red-300 text-red-600 rounded hover:bg-red-50"
        >
          🗑 삭제
        </button>
      </div>
    </div>
  );
}

// ── 메인 ─────────────────────────────────────────────────
export default function WikiGraph() {
  const [nodes, setNodes] = useState<WikiNode[]>([]);
  const [decisions, setDecisions] = useState<WikiDecision[]>([]);
  const [dialogs, setDialogs] = useState<ClarificationDialog[]>([]);
  const [tab, setTab] = useState<Tab>("folders");
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  // Folder 탭 상태
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string>("/");
  const [showCreate, setShowCreate] = useState(false);
  const [newPath, setNewPath] = useState("/");
  const [newDef, setNewDef] = useState("");
  const [newContent, setNewContent] = useState("");

  // Dialog 탭 — single primary thread
  const [userMsg, setUserMsg] = useState("");
  const [lastAction, setLastAction] = useState<{
    action: string;
    message: string;
    wiki_update?: unknown;
    label_fix_target?: Record<string, unknown>;
    pending_amendment?: string[];
  } | null>(null);

  // find_ambiguous
  const [finding, setFinding] = useState(false);
  // agentic_iterate
  const [iterating, setIterating] = useState(false);

  const loadNodes = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const ns = await wikiGraphApi.listNodes();
      setNodes(ns);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRaw = useCallback(async () => {
    try {
      const [ds, dlgs] = await Promise.all([
        wikiGraphApi.listDecisions(200),
        wikiGraphApi.listDialogs(100),
      ]);
      setDecisions(ds);
      setDialogs(dlgs);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => { loadNodes(); }, [loadNodes]);
  useEffect(() => {
    if (tab === "raw" || tab === "dialog") loadRaw();
  }, [tab, loadRaw]);

  const tree = useMemo(() => buildTree(nodes), [nodes]);
  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedId) ?? null,
    [nodes, selectedId],
  );

  const submitCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      const created = await wikiGraphApi.createNode({
        path: normalizePath(newPath),
        definition: newDef,
        content: newContent,
        created_by: "human",
      });
      setMsg(`✅ skill 생성: ${created.definition}`);
      setNewDef("");
      setNewContent("");
      setShowCreate(false);
      await loadNodes();
      setSelectedId(created.id);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const runAgenticIterate = async (dialogID?: string) => {
    setIterating(true);
    setErr(null);
    setMsg(null);
    try {
      const res = await wikiGraphApi.runAgenticIterate(dialogID);
      const summary = [
        res.nodes_created?.length ? `+${res.nodes_created.length} 생성` : "",
        res.nodes_updated?.length ? `${res.nodes_updated.length} 수정` : "",
        res.nodes_deleted?.length ? `-${res.nodes_deleted.length} 삭제` : "",
        res.nodes_moved?.length ? `${res.nodes_moved.length} 이동` : "",
      ].filter(Boolean).join(", ");
      const reasoning = res.reasoning ? `\n💭 "${res.reasoning}"` : "";
      if (res.actions_planned === 0 && (res.errors?.length ?? 0) === 0) {
        setMsg("🤖 Agentic loop: 편집할 것 없음 (현재 구조 OK)" + reasoning);
      } else if (res.errors?.length) {
        setErr(`agentic_iterate 일부 에러: ${res.errors.join(" | ")}`);
      } else {
        setMsg(`🤖 Agentic loop 완료: ${summary || "액션 없음"}${reasoning}`);
      }
      await loadNodes();
      await loadRaw();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setIterating(false);
    }
  };

  const findAmbiguous = async () => {
    setFinding(true);
    setErr(null);
    setMsg(null);
    try {
      const res = await wikiGraphApi.runFindAmbiguous();
      const created = res.dialogs_created?.length ?? 0;
      if (created > 0) {
        setMsg(`🔍 LLM 이 ${res.questions_found}개 질문 생성 (대화 ${created}개)`);
      } else if (res.errors?.length) {
        setErr(
          `LLM 응답 폐기 (모델 크기 한계 가능성). 상세: ${res.errors.join(" | ")}`,
        );
      } else {
        setMsg("경계가 애매한 케이스 없음 — 모든 결정이 명확");
      }
      await loadRaw();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setFinding(false);
    }
  };

  // (legacy helper — 유지만, 현재 chat_continue 로 대체됨)
  void dialogs; void userMsg; void setUserMsg; void lastAction; void setLastAction;

  return (
    <div className="flex-1 h-full flex flex-col min-h-0 min-w-0">
      {/* 헤더 */}
      <div className="px-4 pt-3 pb-2 border-b border-gray-200 bg-white/60 backdrop-blur">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-lg font-bold text-gray-800">G3 Folder Wiki</h1>
            <p className="text-[11px] text-gray-500 mt-0.5 truncate">
              각 노드 = skill · 폴더로 계층화 · LLM 이 agentic loop 로 스스로 편집
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => runAgenticIterate()}
              disabled={iterating}
              title="LLM 이 wiki 전체를 훑어 편집 1회"
              className="text-xs px-3 py-1.5 bg-purple-600 text-white rounded hover:bg-purple-700 disabled:opacity-40 font-medium"
            >
              {iterating ? "🤖 Agentic loop 중..." : "🤖 Agentic loop 1회"}
            </button>
            {tab === "folders" && (
              <button
                onClick={() => setShowCreate(!showCreate)}
                className="text-xs px-3 py-1.5 border border-gray-300 rounded hover:bg-gray-50"
              >
                {showCreate ? "취소" : "+ skill"}
              </button>
            )}
            <button
              onClick={() => { loadNodes(); loadRaw(); }}
              className="text-xs px-3 py-1.5 border border-gray-300 rounded hover:bg-gray-50"
            >
              ↻ 새로고침
            </button>
          </div>
        </div>
        <div className="flex gap-1 mt-2 -mb-2">
          {([
            { id: "folders", label: `📂 Skills (${nodes.length})` },
            { id: "raw",     label: `📋 Raw 결정 (${decisions.length})` },
            { id: "dialog",  label: `💬 LLM 대화 (${dialogs.length})` },
          ] as const).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors ${
                tab === t.id
                  ? "border-boan-600 text-boan-700"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col p-3 gap-3">
        {msg && <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded px-3 py-1.5 whitespace-pre-wrap">{msg}</div>}
        {err && <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-1.5 whitespace-pre-wrap">{err}</div>}

        {/* ── Folders 탭 ── */}
        {tab === "folders" && (
          <div className="flex-1 min-h-0 flex gap-3">
            {/* 좌: 폴더 트리 */}
            <div className="w-80 bg-white border border-gray-200 rounded-xl flex flex-col overflow-hidden">
              <div className="px-3 py-2 border-b border-gray-100 text-xs text-gray-500">
                📂 Skill 트리 ({nodes.length}개)
              </div>
              <div className="flex-1 overflow-y-auto py-1">
                {loading ? (
                  <div className="p-4 text-xs text-gray-400 text-center">로딩 중...</div>
                ) : nodes.length === 0 ? (
                  <div className="p-4 text-xs text-gray-400 text-center">
                    skill 없음.<br/>+ skill 로 추가하거나<br/>Agentic loop 실행.
                  </div>
                ) : (
                  <FolderTree
                    tree={tree}
                    selectedId={selectedId}
                    selectedPath={selectedPath}
                    onPickNode={(id) => { setSelectedId(id); setSelectedPath(""); }}
                    onPickFolder={(p) => { setSelectedPath(p); setSelectedId(null); }}
                  />
                )}
              </div>
            </div>
            {/* 우: skill 내용 또는 폴더 요약 */}
            <div className="flex-1 bg-white border border-gray-200 rounded-xl flex flex-col overflow-hidden min-h-0">
              {showCreate ? (
                <form onSubmit={submitCreate} className="p-4 space-y-2">
                  <div className="text-sm font-semibold text-gray-700">➕ 새 Skill</div>
                  <input
                    value={newPath}
                    onChange={(e) => setNewPath(e.target.value)}
                    placeholder="폴더 경로: /security/credentials"
                    className="w-full text-xs font-mono border border-gray-300 rounded px-2 py-1"
                  />
                  <input
                    value={newDef}
                    onChange={(e) => setNewDef(e.target.value)}
                    maxLength={30}
                    placeholder="Skill 제목 (≤30자)"
                    required
                    className="w-full text-sm border border-gray-300 rounded px-2 py-1"
                  />
                  <textarea
                    value={newContent}
                    onChange={(e) => setNewContent(e.target.value)}
                    maxLength={1000}
                    rows={6}
                    placeholder="본문 (≤1000자). [[node_id|이유]] 인라인 링크 가능."
                    required
                    className="w-full text-xs font-mono border border-gray-300 rounded px-2 py-1"
                  />
                  <button type="submit" className="text-xs px-4 py-1.5 bg-boan-600 text-white rounded hover:bg-boan-700">
                    추가
                  </button>
                </form>
              ) : selectedNode ? (
                <SkillEditor
                  key={selectedNode.id}
                  node={selectedNode}
                  onSaved={() => { setMsg("저장됨"); loadNodes(); }}
                  onDeleted={() => { setSelectedId(null); loadNodes(); }}
                />
              ) : (
                <div className="flex-1 flex items-center justify-center text-sm text-gray-400 text-center px-6">
                  좌측에서 📄 skill 을 선택하세요.<br/>
                  또는 위 "+ skill" 버튼으로 추가.
                  {selectedPath && selectedPath !== "/" && (
                    <>
                      <br/><br/>
                      <span className="text-xs">현재 선택 폴더: <code className="bg-gray-100 px-1">{selectedPath}</code></span>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Raw 결정 탭 ── */}
        {tab === "raw" && (
          <div className="flex-1 min-h-0 bg-white border border-gray-200 rounded-xl overflow-hidden flex flex-col">
            <div className="px-4 py-2 border-b border-gray-100 text-xs text-gray-500">
              HITL approve/deny 라벨 이력 (최근 200건) — LLM 이 관찰하는 원시 데이터
            </div>
            <div className="flex-1 overflow-auto">
              <table className="w-full text-xs">
                <thead className="bg-gray-50 text-left text-gray-500 sticky top-0">
                  <tr>
                    <th className="px-3 py-2 font-medium w-32">시각</th>
                    <th className="px-3 py-2 font-medium w-20">결정</th>
                    <th className="px-3 py-2 font-medium w-40">이유</th>
                    <th className="px-3 py-2 font-medium">입력 원문</th>
                    <th className="px-3 py-2 font-medium w-24">라벨러</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {decisions.length === 0 ? (
                    <tr><td colSpan={5} className="text-center py-12 text-gray-400">아직 라벨링된 결정이 없습니다.</td></tr>
                  ) : decisions.map((d) => (
                    <tr key={d.id} className={d.decision === "approve" ? "" : "bg-red-50/30"}>
                      <td className="px-3 py-2 text-[10px] text-gray-400 font-mono">
                        {d.timestamp ? new Date(d.timestamp).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "-"}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                          d.decision === "approve" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
                        }`}>{d.decision}</span>
                      </td>
                      <td className="px-3 py-2 text-gray-600 text-[11px]">{d.reason}</td>
                      <td className="px-3 py-2 text-gray-800 font-mono text-[11px] break-all">{d.input}</td>
                      <td className="px-3 py-2 text-gray-400 text-[10px]">{d.labeler}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Dialog 탭 ── */}
        {tab === "dialog" && (() => {
          // ── 단일 통합 대화 (primary) ────────────────────────────
          // 여러 dialog 이 있으면 첫 번째를 primary 로 사용 (나머지는 backend
          // CLOSE_AND_FIND_NEW 가 자동 정리). UI 는 하나의 연속된 chat.
          const primary = dialogs[0];
          return (
            <div className="flex-1 min-h-0 flex flex-col bg-white border border-gray-200 rounded-xl overflow-hidden">
              <div className="px-4 py-2 border-b border-gray-100 flex items-center justify-between">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-gray-700">💬 G3 Wiki 대화 (agentic loop)</div>
                  <div className="text-[10px] text-gray-500">
                    {primary
                      ? `${primary.turns.length} 턴 · LLM 이 애매한 경계를 찾고 당신 답변을 반영 → wiki 진화. ASK / FIX / UPDATE / CLOSE 분기`
                      : "대화 없음. 아래 버튼으로 첫 질문을 LLM 이 생성하도록 요청"}
                  </div>
                </div>
                {!primary && (
                  <button
                    onClick={findAmbiguous}
                    disabled={finding}
                    className="text-xs px-3 py-1.5 bg-boan-600 text-white rounded hover:bg-boan-700 disabled:opacity-40 font-medium"
                  >
                    {finding ? "🔍 분석 중..." : "🔍 첫 질문 생성"}
                  </button>
                )}
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-3">
                {primary ? (
                  primary.turns.map((t, i) => <DialogTurnView key={i} turn={t} />)
                ) : (
                  <div className="h-full flex items-center justify-center text-sm text-gray-400 text-center">
                    아직 대화가 없습니다. 상단 '🔍 첫 질문 생성' 을 누르면 LLM 이 과거 decision 중 애매한 경계를 찾아 첫 질문을 만듭니다.
                  </div>
                )}
                {iterating && <div className="text-[10px] text-gray-400 italic">LLM 이 응답 생성 중...</div>}
              </div>
              {primary && (
                <div className="border-t border-gray-100 p-3 flex gap-2">
                  <textarea
                    value={userMsg}
                    onChange={(e) => setUserMsg(e.target.value)}
                    placeholder="답변 입력... (LLM 이 action 결정: ASK / FIX / UPDATE / CLOSE_AND_NEW)"
                    rows={2}
                    className="flex-1 text-xs border border-gray-200 rounded px-2 py-1 resize-none"
                  />
                  <button
                    disabled={!userMsg.trim() || iterating}
                    onClick={async () => {
                      const answer = userMsg.trim();
                      setUserMsg("");
                      setIterating(true);
                      try {
                        await wikiGraphApi.upsertDialog({ ...primary, turns: [...primary.turns, { role: "human", content: answer }] });
                        const res = await wikiGraphApi.chatContinue(primary.id!);
                        setLastAction(res);
                        await loadRaw();
                        if (res.action === "UPDATE_WIKI") await loadNodes();
                      } catch (e) {
                        setErr(e instanceof Error ? e.message : String(e));
                      } finally {
                        setIterating(false);
                      }
                    }}
                    className="text-xs px-4 py-1 bg-boan-600 text-white rounded hover:bg-boan-700 disabled:opacity-40 self-end"
                  >
                    답변 + 🤖
                  </button>
                </div>
              )}
              {lastAction && (
                <div className="border-t border-gray-100 px-4 py-2 text-[11px] flex items-center gap-3 bg-gray-50">
                  <span className="font-medium text-gray-600">마지막 action:</span>
                  <span className={`px-2 py-0.5 rounded ${
                    lastAction.action === "UPDATE_WIKI" ? "bg-green-100 text-green-700" :
                    lastAction.action === "CLOSE_AND_FIND_NEW" ? "bg-blue-100 text-blue-700" :
                    lastAction.action === "REQUEST_LABEL_FIX" ? "bg-orange-100 text-orange-700" :
                    "bg-gray-100 text-gray-600"
                  }`}>{lastAction.action}</span>
                  {(() => {
                    const wu = lastAction.wiki_update as { actions_planned?: number } | null | undefined;
                    if (!wu || typeof wu !== "object") return null;
                    const n: number = wu.actions_planned ?? 0;
                    return <span className="text-gray-500">wiki 변경 {n} 건</span>;
                  })()}
                </div>
              )}
              {/* REQUEST_LABEL_FIX 제안 카드 — Accept/Reject 로 사용자 결정 받아야 실제 적용 */}
              {lastAction && lastAction.action === "REQUEST_LABEL_FIX" && lastAction.label_fix_target && (
                <LabelFixProposal
                  target={lastAction.label_fix_target as Record<string, unknown>}
                  onApplied={async () => {
                    await loadRaw();
                    setLastAction(null);
                  }}
                  onDismiss={() => setLastAction(null)}
                />
              )}
              {/* UPDATE_WIKI 후 큰 변경 — 자동 개정 제안이 Approvals 에 등록됨 */}
              {lastAction && Array.isArray(lastAction.pending_amendment) && lastAction.pending_amendment.length > 0 && (
                <div className="mx-4 my-3 rounded-lg border-2 border-blue-300 bg-blue-50 p-3 text-xs">
                  <div className="font-semibold text-blue-800 mb-1">
                    🔔 Wiki 변경이 커서 자동 개정 제안을 생성했습니다
                  </div>
                  <div className="text-blue-700 mb-2">
                    G1 (정규식) / G2 (헌법) 개정 diff 가 <strong>Approvals 탭</strong> 에 pending 으로 등록됐습니다.
                    내용 확인 후 수락하면 정책 버전 ++.
                  </div>
                  <div className="flex gap-1 flex-wrap text-[10px] font-mono">
                    {lastAction.pending_amendment.map((id, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-blue-200 text-blue-900">{id}</span>
                    ))}
                  </div>
                  <a href="/approvals" className="mt-2 inline-block text-xs text-blue-700 underline">
                    → Approvals 탭 열기
                  </a>
                </div>
              )}
            </div>
          );
        })()}
      </div>
    </div>
  );
}

function DialogTurnView({ turn }: { turn: DialogTurn }) {
  const isLLM = turn.role === "llm";
  return (
    <div className={`flex ${isLLM ? "justify-start" : "justify-end"}`}>
      <div
        className={`max-w-[80%] rounded-lg px-3 py-2 text-xs ${
          isLLM ? "bg-boan-50 border border-boan-200 text-gray-800" : "bg-boan-600 text-white"
        }`}
      >
        <div className={`text-[10px] font-semibold mb-1 ${isLLM ? "text-boan-700" : "text-boan-100"}`}>
          {isLLM ? "🤖 LLM" : "👤 사람"}
        </div>
        <div className="whitespace-pre-wrap leading-relaxed">{turn.content}</div>
        {turn.examples && turn.examples.length > 0 && (
          <div className="mt-2 pt-2 border-t border-white/20">
            <div className="text-[10px] font-semibold mb-1 opacity-70">예시:</div>
            <ul className="space-y-1">
              {turn.examples.map((ex, i) => (
                <li key={i} className="text-[11px] font-mono opacity-90 pl-2 border-l-2 border-white/30">
                  {ex}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

// LabelFixProposal — LLM 이 REQUEST_LABEL_FIX 로 제안한 decision 재라벨을
// 사용자가 Accept/Reject 하는 카드. Accept 시에만 실제 decision store 수정.
function LabelFixProposal({
  target,
  onApplied,
  onDismiss,
}: {
  target: Record<string, unknown>;
  onApplied: () => void | Promise<void>;
  onDismiss: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decisionID = (target.decision_id as string) || "";
  const decisionText = (target.decision_text as string) || "";
  const currentLabel = (target.current_label as string) || "?";
  const suggestedLabel = (target.suggested_label as string) || "";
  const reason = (target.reason as string) || "";

  const canApply = Boolean(decisionID && (suggestedLabel === "approve" || suggestedLabel === "deny"));

  const handleAccept = async () => {
    if (!canApply) {
      setError("decision_id 또는 suggested_label 누락 — LLM 응답 확인 필요");
      return;
    }
    setBusy(true); setError(null);
    try {
      await wikiGraphApi.labelFixApply(decisionID, suggestedLabel as "approve" | "deny", reason);
      await onApplied();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-4 my-3 rounded-lg border-2 border-orange-300 bg-orange-50 p-3 text-xs">
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="font-semibold text-orange-800">
          🏷️ LLM 재라벨 제안 — 승인하시겠습니까?
        </div>
        <button
          onClick={onDismiss}
          disabled={busy}
          className="text-orange-600 hover:text-orange-800 text-[10px]"
          title="닫기 (적용 안 함)"
        >
          ✕
        </button>
      </div>
      <div className="space-y-1 mb-3">
        <div><span className="text-orange-600">대상 결정:</span> <code className="bg-white px-1 rounded text-[10px]">{decisionText || decisionID || "(unknown)"}</code></div>
        <div>
          <span className="text-orange-600">변경:</span>{" "}
          <span className="inline-flex items-center gap-1">
            <span className="px-1.5 py-0.5 rounded bg-gray-200 text-gray-700 text-[10px] line-through">{currentLabel}</span>
            <span>→</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${suggestedLabel === "deny" ? "bg-red-200 text-red-800" : "bg-green-200 text-green-800"}`}>{suggestedLabel}</span>
          </span>
        </div>
        {reason && <div className="text-orange-700"><span className="text-orange-600">이유:</span> {reason}</div>}
      </div>
      {error && <div className="mb-2 text-red-700 text-[11px]">{error}</div>}
      <div className="flex gap-2">
        <button
          onClick={handleAccept}
          disabled={busy || !canApply}
          className="px-3 py-1.5 rounded bg-orange-600 text-white text-[11px] font-medium hover:bg-orange-700 disabled:opacity-50"
        >
          {busy ? "적용 중..." : "✓ 수락 — 적용"}
        </button>
        <button
          onClick={onDismiss}
          disabled={busy}
          className="px-3 py-1.5 rounded border border-gray-300 bg-white text-gray-700 text-[11px] hover:bg-gray-50"
        >
          거절
        </button>
      </div>
    </div>
  );
}
