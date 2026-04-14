// WikiGraph — LLM 이 편집하는 지식 그래프 시각화.
// Notion 스타일 inline link [[id|reason]] 지원.
// react-flow 방향 그래프 + dagre 자동 레이아웃.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useReactFlow,
  type Node,
  type Edge,
  type NodeProps,
  Handle,
  Position,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import {
  wikiGraphApi,
  type WikiNode,
  type WikiEdge,
  type WikiDecision,
  type ClarificationDialog,
  type DialogTurn,
} from "../api";

// ── relation 별 색상/스타일 ──────────────────────────────
const RELATION_STYLES: Record<string, { stroke: string; label: string }> = {
  supports:     { stroke: "#16a34a", label: "뒷받침" },
  contradicts:  { stroke: "#dc2626", label: "모순" },
  refines:      { stroke: "#0891b2", label: "정교화" },
  example_of:   { stroke: "#ca8a04", label: "예시" },
  depends_on:   { stroke: "#7c3aed", label: "전제" },
  evolved_from: { stroke: "#4b5563", label: "진화" },
  inline_ref:   { stroke: "#64748b", label: "본문링크" },
};

function relStyle(r: string) {
  return RELATION_STYLES[r] ?? { stroke: "#94a3b8", label: r };
}

// ── 자동 레이아웃 (dagre) ───────────────────────────────
function layoutGraph(nodes: Node[], edges: Edge[], direction: "LR" | "TB" = "TB") {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, nodesep: 60, ranksep: 80 });
  nodes.forEach((n) => g.setNode(n.id, { width: 220, height: 100 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const pos = g.node(n.id);
    return { ...n, position: { x: pos.x - 110, y: pos.y - 50 } };
  });
}

// ── Custom 노드 컴포넌트 ─────────────────────────────────
function WikiNodeView({ data }: NodeProps) {
  const d = data as { definition: string; content: string; tags?: string[] };
  return (
    <div className="bg-white border border-gray-300 rounded-xl shadow-sm px-3 py-2 w-[220px] hover:shadow-md transition-shadow">
      <Handle type="target" position={Position.Top} />
      <div className="text-[11px] font-bold text-gray-800 truncate" title={d.definition}>
        {d.definition || "(제목 없음)"}
      </div>
      <div className="text-[10px] text-gray-500 mt-1 line-clamp-2 leading-tight">
        {(d.content || "").replace(/\[\[[^\]]+\]\]/g, "🔗")}
      </div>
      {d.tags && d.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5">
          {d.tags.slice(0, 3).map((t) => (
            <span
              key={t}
              className="text-[9px] px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded-full"
            >
              {t}
            </span>
          ))}
          {d.tags.length > 3 && (
            <span className="text-[9px] text-gray-400">+{d.tags.length - 3}</span>
          )}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

const nodeTypes = { wiki: WikiNodeView };

// ── 본문 inline link 렌더 ────────────────────────────────
function renderContent(content: string, nodes: Map<string, WikiNode>, onClick: (id: string) => void) {
  // [[id|reason]] 또는 [[id]] 를 찾아 클릭 가능한 span 으로.
  const parts: React.ReactNode[] = [];
  let i = 0;
  const re = /\[\[([a-zA-Z0-9_\-]+)(?:\|([^\]]*))?\]\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m.index > i) parts.push(content.slice(i, m.index));
    const id = m[1];
    const reason = m[2] ?? "";
    const target = nodes.get(id);
    const label = target ? target.definition : id;
    parts.push(
      <button
        key={`${m.index}_${id}`}
        onClick={() => onClick(id)}
        className={`inline-block px-1.5 py-0.5 mx-0.5 rounded text-[11px] font-medium ${
          target
            ? "bg-boan-50 text-boan-700 hover:bg-boan-100 border border-boan-200"
            : "bg-red-50 text-red-600 border border-red-200 line-through"
        }`}
        title={reason || (target ? target.content.slice(0, 80) : "대상 노드 없음")}
      >
        🔗 {label}
      </button>
    );
    i = m.index + m[0].length;
  }
  if (i < content.length) parts.push(content.slice(i));
  return <>{parts}</>;
}

// 노드 변경 시 fitView 자동 호출하는 inner 컴포넌트.
function GraphCanvas({ flowNodes, flowEdges, onNodeClick, onPaneClick }: {
  flowNodes: Node[]; flowEdges: Edge[]; onNodeClick: (id: string) => void; onPaneClick: () => void;
}) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    if (flowNodes.length > 0) {
      // 두 번 호출 — 한 번은 즉시(레이아웃 후), 한 번은 이미지/엣지 계산 후.
      const t1 = setTimeout(() => fitView({ padding: 0.15, duration: 0, maxZoom: 4 }), 100);
      const t2 = setTimeout(() => fitView({ padding: 0.15, duration: 400, maxZoom: 4 }), 500);
      return () => { clearTimeout(t1); clearTimeout(t2); };
    }
  }, [flowNodes, fitView]);
  return (
    <ReactFlow
      nodes={flowNodes}
      edges={flowEdges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.1}
      maxZoom={3}
      onNodeClick={(_, n) => onNodeClick(n.id)}
      onPaneClick={onPaneClick}
    >
      <Background gap={16} />
      <Controls />
      <MiniMap pannable zoomable />
    </ReactFlow>
  );
}

// ── 메인 컴포넌트 ────────────────────────────────────────
export default function WikiGraph() {
  const [nodes, setNodes] = useState<WikiNode[]>([]);
  const [edges, setEdges] = useState<WikiEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  // Manual node create
  const [showCreate, setShowCreate] = useState(false);
  const [newDef, setNewDef] = useState("");
  const [newContent, setNewContent] = useState("");
  const [newTags, setNewTags] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  // Run skill.wiki_edit
  const [skillInput, setSkillInput] = useState("");
  const [skillDecision, setSkillDecision] = useState<"approve" | "deny">("deny");
  const [skillRunning, setSkillRunning] = useState(false);

  // Layout
  const [direction, setDirection] = useState<"LR" | "TB">("LR");

  // Tab + raw data + dialog
  type Tab = "graph" | "raw" | "dialog";
  const [tab, setTab] = useState<Tab>("graph");
  const [decisions, setDecisions] = useState<WikiDecision[]>([]);
  const [dialogs, setDialogs] = useState<ClarificationDialog[]>([]);
  const [activeDialog, setActiveDialog] = useState<string | null>(null);
  const [userMsg, setUserMsg] = useState("");

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

  useEffect(() => {
    if (tab === "raw" || tab === "dialog") loadRaw();
  }, [tab, loadRaw]);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const [ns, es] = await Promise.all([
        wikiGraphApi.listNodes(),
        wikiGraphApi.listEdges(),
      ]);
      setNodes(ns);
      setEdges(es);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  // react-flow 용 변환 + 레이아웃.
  const flowNodes: Node[] = useMemo(() => {
    const base = nodes.map((n) => ({
      id: n.id,
      type: "wiki",
      position: { x: 0, y: 0 },
      data: { definition: n.definition, content: n.content, tags: n.tags },
    }));
    return layoutGraph(
      base,
      edges.filter((e) => nodeMap.has(e.from) && nodeMap.has(e.to)).map((e) => ({
        id: e.id, source: e.from, target: e.to,
      })),
      direction,
    );
  }, [nodes, edges, nodeMap, direction]);

  const flowEdges: Edge[] = useMemo(
    () =>
      edges
        .filter((e) => nodeMap.has(e.from) && nodeMap.has(e.to))
        .map((e) => {
          const s = relStyle(e.relation);
          return {
            id: e.id,
            source: e.from,
            target: e.to,
            label: s.label + (e.reason ? ` · ${e.reason.slice(0, 10)}…` : ""),
            labelStyle: { fontSize: 10, fill: s.stroke },
            style: { stroke: s.stroke, strokeWidth: 1.5 },
            markerEnd: { type: MarkerType.ArrowClosed, color: s.stroke },
            animated: e.relation === "inline_ref",
          };
        }),
    [edges, nodeMap],
  );

  const selectedNode = selected ? nodeMap.get(selected) : null;
  const selectedEdges = selected
    ? edges.filter((e) => e.from === selected || e.to === selected)
    : [];

  const submitCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await wikiGraphApi.createNode({
        definition: newDef.trim(),
        content: newContent,
        tags: newTags.split(",").map((s) => s.trim()).filter(Boolean),
        created_by: "human",
      });
      setNewDef(""); setNewContent(""); setNewTags("");
      setShowCreate(false);
      setMsg("노드 추가됨");
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const runSkill = async () => {
    if (!skillInput.trim()) return;
    setSkillRunning(true);
    setMsg(null);
    try {
      const res = await wikiGraphApi.runWikiEdit({
        input: skillInput.trim(),
        decision: skillDecision,
        labeler: "manual",
      });
      setMsg(`skill.wiki_edit → +${res.nodes_created?.length ?? 0} node / +${res.edges_created?.length ?? 0} edge / ${res.errors?.length ?? 0} 에러`);
      setSkillInput("");
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSkillRunning(false);
    }
  };

  const deleteNode = async (id: string) => {
    if (!confirm("이 노드 + 연결 엣지를 삭제하시겠습니까?")) return;
    try {
      await wikiGraphApi.deleteNode(id);
      setSelected(null);
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const appendTurn = async (dialogID: string, role: "human" | "llm", content: string) => {
    const d = dialogs.find((x) => x.id === dialogID);
    if (!d) return;
    const next: ClarificationDialog = {
      ...d,
      turns: [...d.turns, { role, content }],
    };
    await wikiGraphApi.upsertDialog(next);
    loadRaw();
  };

  const [finding, setFinding] = useState(false);
  const findAmbiguous = async () => {
    setFinding(true);
    setErr(null);
    setMsg(null);
    try {
      const res = await wikiGraphApi.runFindAmbiguous();
      setMsg(
        `LLM 이 애매한 경계 ${res.questions_found}개 발견, 대화 ${
          res.dialogs_created?.length ?? 0
        }개 생성${res.errors?.length ? ` (에러 ${res.errors.length})` : ""}`,
      );
      await loadRaw();
      if ((res.dialogs_created?.length ?? 0) > 0) {
        setActiveDialog(res.dialogs_created[0]);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setFinding(false);
    }
  };

  return (
    <div className="flex-1 h-full flex flex-col min-h-0 min-w-0">
      {/* 상단 타이틀 + 탭 + 컨트롤 */}
      <div className="px-4 pt-3 pb-2 border-b border-gray-200 bg-white/60 backdrop-blur">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-lg font-bold text-gray-800">G3 Graph Wiki</h1>
            <p className="text-[11px] text-gray-500 mt-0.5 truncate">
              LLM 이 HITL 결정을 보고 스스로 편집/질문하는 지식 그래프 · Graph + Raw 결정 + LLM 주도 Q&A
            </p>
          </div>
          <div className="flex items-center gap-2">
            {tab === "graph" && (
              <>
                <select
                  value={direction}
                  onChange={(e) => setDirection(e.target.value as "LR" | "TB")}
                  className="text-xs border border-gray-300 rounded px-2 py-1"
                >
                  <option value="LR">가로 배치</option>
                  <option value="TB">세로 배치</option>
                </select>
                <button
                  onClick={() => setShowCreate(!showCreate)}
                  className="text-xs px-3 py-1.5 border border-gray-300 rounded hover:bg-gray-50"
                >
                  {showCreate ? "취소" : "+ 노드"}
                </button>
              </>
            )}
            <button
              onClick={() => { load(); loadRaw(); }}
              className="text-xs px-3 py-1.5 border border-gray-300 rounded hover:bg-gray-50"
            >
              ↻ 새로고침
            </button>
          </div>
        </div>
        {/* 탭 */}
        <div className="flex gap-1 mt-2 -mb-2">
          {([
            { id: "graph",  label: `🕸️ Graph (${nodes.length})` },
            { id: "raw",    label: `📋 Raw 결정 (${decisions.length})` },
            { id: "dialog", label: `💬 LLM 대화 (${dialogs.length})` },
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

      {/* 이 아래는 탭 별 본문 wrapper */}
      <div className="flex-1 min-h-0 flex flex-col p-3 gap-3">
      {tab === "graph" && (<>
      {/* skill.wiki_edit 테스트 */}
      <div className="bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 rounded-lg p-3">
        <div className="text-xs font-medium text-gray-700 mb-1.5">⚡ skill.wiki_edit 수동 실행 (LLM 이 그래프 편집)</div>
        <div className="flex gap-2">
          <select
            value={skillDecision}
            onChange={(e) => setSkillDecision(e.target.value as "approve" | "deny")}
            className="text-xs border border-gray-300 rounded px-2 py-1 bg-white"
          >
            <option value="deny">deny (위험)</option>
            <option value="approve">approve (안전)</option>
          </select>
          <input
            value={skillInput}
            onChange={(e) => setSkillInput(e.target.value)}
            placeholder="입력 예시 — 예: 고객 개인정보 김철수 010-1234-5678 ..."
            className="flex-1 text-xs border border-gray-300 rounded px-2 py-1 bg-white"
          />
          <button
            onClick={runSkill}
            disabled={skillRunning || !skillInput.trim()}
            className="text-xs px-3 py-1 bg-boan-600 text-white rounded hover:bg-boan-700 disabled:opacity-40"
          >
            {skillRunning ? "LLM 호출중..." : "실행"}
          </button>
        </div>
      </div>

      {/* 노드 추가 폼 */}
      {showCreate && (
        <form onSubmit={submitCreate} className="mb-3 bg-white border border-gray-200 rounded-lg p-3 space-y-2">
          <input
            value={newDef}
            onChange={(e) => setNewDef(e.target.value)}
            placeholder="정의 (30자 이내)"
            maxLength={30}
            required
            className="w-full text-xs border border-gray-300 rounded px-2 py-1"
          />
          <textarea
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder="내용 (1000자 이내). 다른 노드 링크는 [[node_id|이유]] 문법 사용"
            maxLength={1000}
            rows={3}
            required
            className="w-full text-xs border border-gray-300 rounded px-2 py-1 font-mono"
          />
          <div className="flex gap-2">
            <input
              value={newTags}
              onChange={(e) => setNewTags(e.target.value)}
              placeholder="태그 (쉼표로 구분)"
              className="flex-1 text-xs border border-gray-300 rounded px-2 py-1"
            />
            <button type="submit" className="text-xs px-3 py-1 bg-boan-600 text-white rounded hover:bg-boan-700">
              추가
            </button>
          </div>
        </form>
      )}

      {msg && <div className="mb-2 text-xs text-green-600 bg-green-50 border border-green-200 rounded px-2 py-1">{msg}</div>}
      {err && <div className="mb-2 text-xs text-red-600 bg-red-50 border border-red-200 rounded px-2 py-1">{err}</div>}

      {/* 그래프 + drawer — 남은 viewport 전부 채움 */}
      <div className="flex gap-3 flex-1 min-h-0">
        <div className="flex-1 bg-white border border-gray-200 rounded-xl overflow-hidden min-h-0">
          {loading ? (
            <div className="h-full flex items-center justify-center text-sm text-gray-400">로딩 중...</div>
          ) : flowNodes.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-sm text-gray-400 gap-2">
              <div>아직 노드가 없습니다.</div>
              <div className="text-xs">위 skill.wiki_edit 에 입력 넣고 실행하거나 "+ 노드" 로 수동 추가.</div>
            </div>
          ) : (
            <ReactFlowProvider>
              <GraphCanvas
                flowNodes={flowNodes}
                flowEdges={flowEdges}
                onNodeClick={(id) => setSelected(id)}
                onPaneClick={() => setSelected(null)}
              />
            </ReactFlowProvider>
          )}
        </div>

        {/* drawer */}
        {selectedNode && (
          <div className="w-96 bg-white border border-gray-200 rounded-xl p-4 overflow-y-auto min-h-0">
            <div className="flex items-start justify-between gap-2 mb-2">
              <h2 className="text-sm font-bold text-gray-800">{selectedNode.definition}</h2>
              <button
                onClick={() => setSelected(null)}
                className="text-gray-400 hover:text-gray-700 text-lg leading-none"
              >
                ×
              </button>
            </div>
            <div className="text-[10px] text-gray-400 mb-3 font-mono">{selectedNode.id}</div>
            <div className="text-xs text-gray-700 leading-relaxed whitespace-pre-wrap mb-3">
              {renderContent(selectedNode.content, nodeMap, (id) => setSelected(id))}
            </div>
            {selectedNode.tags && selectedNode.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-3">
                {selectedNode.tags.map((t) => (
                  <span key={t} className="text-[10px] px-2 py-0.5 bg-blue-50 text-blue-700 rounded-full">{t}</span>
                ))}
              </div>
            )}
            <div className="text-[10px] text-gray-400 mb-3">
              by {selectedNode.created_by ?? "?"} · {selectedNode.updated_at?.slice(0, 19)}
            </div>

            {selectedEdges.length > 0 && (
              <div className="border-t border-gray-100 pt-3">
                <div className="text-[10px] font-semibold text-gray-500 mb-1.5">연결 ({selectedEdges.length})</div>
                <div className="space-y-1">
                  {selectedEdges.map((e) => {
                    const s = relStyle(e.relation);
                    const otherID = e.from === selected ? e.to : e.from;
                    const other = nodeMap.get(otherID);
                    const dir = e.from === selected ? "→" : "←";
                    return (
                      <button
                        key={e.id}
                        onClick={() => other && setSelected(otherID)}
                        className="w-full text-left text-xs text-gray-700 px-2 py-1.5 rounded hover:bg-gray-50 border border-gray-100"
                        disabled={!other}
                      >
                        <span style={{ color: s.stroke }} className="font-medium">{dir} {s.label}</span>
                        <span className="text-gray-500"> · {other?.definition ?? `(${otherID} 없음)`}</span>
                        {e.reason && <div className="text-[10px] text-gray-400 ml-4">{e.reason}</div>}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="border-t border-gray-100 pt-3 mt-3">
              <button
                onClick={() => deleteNode(selectedNode.id)}
                className="w-full text-xs text-red-500 hover:text-red-700 py-1.5 border border-red-200 hover:bg-red-50 rounded"
              >
                노드 삭제
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 범례 */}
      <div className="flex flex-wrap gap-3 text-[10px] text-gray-500">
        <span className="font-semibold">관계:</span>
        {Object.entries(RELATION_STYLES).map(([k, v]) => (
          <span key={k} className="flex items-center gap-1">
            <span style={{ background: v.stroke, width: 12, height: 2, display: "inline-block" }} />
            {v.label}
          </span>
        ))}
      </div>
      </>)}

      {/* ── Raw 결정 탭 ── */}
      {tab === "raw" && (
        <div className="flex-1 min-h-0 bg-white border border-gray-200 rounded-xl overflow-hidden flex flex-col">
          <div className="px-3 py-2 border-b border-gray-100 text-xs text-gray-500 flex-shrink-0">
            HITL approve/deny 라벨 이력 (최근 200건) — LLM 이 관찰하는 원시 데이터
          </div>
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="bg-gray-50 border-b border-gray-200 sticky top-0">
                <tr>
                  <th className="text-left px-3 py-2 font-semibold text-gray-500 w-32">시각</th>
                  <th className="text-left px-3 py-2 font-semibold text-gray-500 w-20">결정</th>
                  <th className="text-left px-3 py-2 font-semibold text-gray-500 w-28">이유</th>
                  <th className="text-left px-3 py-2 font-semibold text-gray-500">입력 원문</th>
                  <th className="text-left px-3 py-2 font-semibold text-gray-500 w-24">라벨러</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {decisions.length === 0 ? (
                  <tr><td colSpan={5} className="text-center py-8 text-gray-400">아직 라벨링된 결정이 없습니다.</td></tr>
                ) : decisions.map((d, i) => (
                  <tr key={d.id ?? i} className={d.decision === "deny" ? "bg-red-50/30" : "bg-green-50/30"}>
                    <td className="px-3 py-1.5 text-gray-400 font-mono whitespace-nowrap">
                      {d.timestamp ? new Date(d.timestamp).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "-"}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${
                        d.decision === "approve" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
                      }`}>
                        {d.decision}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-gray-600 truncate max-w-[180px]" title={d.reason}>
                      {d.reason || "-"}
                    </td>
                    <td className="px-3 py-1.5 text-gray-700 font-mono truncate max-w-[600px]" title={d.input}>
                      {d.input}
                    </td>
                    <td className="px-3 py-1.5 text-gray-400">{d.labeler || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── LLM↔Human 대화 탭 ── */}
      {tab === "dialog" && (
        <div className="flex-1 min-h-0 flex gap-3">
          {/* 좌측: 대화 목록 */}
          <div className="w-80 bg-white border border-gray-200 rounded-xl flex flex-col overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-100 flex flex-col gap-1.5">
              <button
                onClick={findAmbiguous}
                disabled={finding}
                className="text-xs px-3 py-2 bg-boan-600 text-white rounded hover:bg-boan-700 disabled:opacity-40 font-medium"
              >
                {finding ? "🔍 LLM 분석 중..." : "🔍 LLM 이 애매한 경계 찾기"}
              </button>
              <div className="text-[10px] text-gray-500 leading-tight">
                최근 approve/deny 결정에서 경계가 애매한 케이스를 LLM 이 스스로 찾아 질문을 생성합니다.
              </div>
            </div>
            <div className="flex-1 overflow-y-auto divide-y divide-gray-100">
              {dialogs.length === 0 ? (
                <div className="p-4 text-center text-xs text-gray-400">
                  아직 질문 없음.<br />
                  위 버튼을 눌러 LLM 이 최근 HITL 결정에서<br />
                  애매한 경계를 찾도록 시키세요.
                </div>
              ) : dialogs.map((d) => (
                <button
                  key={d.id}
                  onClick={() => setActiveDialog(d.id ?? null)}
                  className={`w-full text-left px-3 py-2 hover:bg-gray-50 ${
                    activeDialog === d.id ? "bg-boan-50" : ""
                  }`}
                >
                  <div className="text-xs font-medium text-gray-700 truncate">
                    {d.turns[0]?.content.slice(0, 40) ?? "(비어있음)"}
                  </div>
                  <div className="text-[10px] text-gray-400 mt-0.5 flex justify-between">
                    <span>{d.turns.length} 턴</span>
                    <span>{d.started_at ? new Date(d.started_at).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" }) : ""}</span>
                  </div>
                  {d.topic_node_id && (
                    <div className="text-[10px] text-boan-600 font-mono mt-0.5">🔗 {d.topic_node_id.slice(0, 24)}</div>
                  )}
                </button>
              ))}
            </div>
          </div>
          {/* 우측: 대화 본문 */}
          <div className="flex-1 bg-white border border-gray-200 rounded-xl flex flex-col overflow-hidden">
            {activeDialog ? (() => {
              const d = dialogs.find((x) => x.id === activeDialog);
              if (!d) return <div className="p-6 text-sm text-gray-400">대화를 찾을 수 없음</div>;
              return <>
                <div className="px-4 py-2 border-b border-gray-100 flex items-center justify-between">
                  <div className="text-xs text-gray-500">
                    {d.turns.length} 턴 · 시작 {d.started_at ? new Date(d.started_at).toLocaleString("ko-KR") : "-"}
                  </div>
                  {d.topic_node_id && (
                    <button
                      onClick={() => { setSelected(d.topic_node_id!); setTab("graph"); }}
                      className="text-[11px] text-boan-600 hover:underline font-mono"
                    >
                      🔗 노드로 이동: {d.topic_node_id.slice(0, 20)}
                    </button>
                  )}
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-3">
                  {d.turns.map((t, i) => (
                    <DialogTurnView key={i} turn={t} />
                  ))}
                </div>
                <div className="border-t border-gray-100 p-3 flex gap-2">
                  <textarea
                    value={userMsg}
                    onChange={(e) => setUserMsg(e.target.value)}
                    placeholder="사용자 답변을 여기에 입력..."
                    rows={2}
                    className="flex-1 text-xs border border-gray-200 rounded px-2 py-1 resize-none"
                  />
                  <button
                    disabled={!userMsg.trim()}
                    onClick={async () => {
                      await appendTurn(d.id!, "human", userMsg.trim());
                      setUserMsg("");
                    }}
                    className="text-xs px-4 py-1 bg-boan-600 text-white rounded hover:bg-boan-700 disabled:opacity-40 self-end"
                  >
                    답변
                  </button>
                </div>
              </>;
            })() : (
              <div className="flex-1 flex items-center justify-center text-sm text-gray-400 text-center px-6">
                좌측에서 LLM 이 생성한 질문을 선택하세요.<br />
                아직 질문이 없다면 "🔍 LLM 이 애매한 경계 찾기" 버튼으로 시작.
              </div>
            )}
          </div>
        </div>
      )}

      </div>
    </div>
  );
}

// ── DialogTurn 렌더 ────────────────────────────────────
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
