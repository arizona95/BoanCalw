import { useEffect, useMemo, useState, useCallback } from "react";

interface FileEntry {
  name: string;
  is_dir: boolean;
  size: number;
  modified: number; // unix seconds
}

type Side = "s2" | "s1";
type SortBy = "modified" | "name";

const SIDE_LABEL: Record<Side, string> = {
  s2: "S2 Sandbox (Mount)",
  s1: "S1 GCP (Workstation)",
};

const SIDE_COLOR: Record<Side, string> = {
  s2: "border-blue-400 bg-blue-50",
  s1: "border-orange-400 bg-orange-50",
};

async function listFiles(side: Side, path: string): Promise<{ files: FileEntry[]; path: string }> {
  const res = await fetch(`/api/files/list?side=${side}&path=${encodeURIComponent(path)}`, { credentials: "include" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function transferFile(fileName: string, srcSide: Side, srcPath: string, dstPath: string): Promise<{ ok: boolean; error?: string; reason?: string }> {
  const res = await fetch("/api/files/transfer", {
    method: "POST", credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file_name: fileName, src_side: srcSide, src_path: srcPath, dst_path: dstPath }),
  });
  return res.json();
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// 폴더 탐색기 관례: 디렉토리를 항상 위에 고정하고 그 안에서 선택된 기준으로 정렬.
// modified 는 최신 우선(desc), name 은 가나다/알파벳(asc, locale-aware).
function sortFiles(files: FileEntry[], sortBy: SortBy): FileEntry[] {
  const sorted = [...files];
  sorted.sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    if (sortBy === "modified") {
      if (b.modified !== a.modified) return b.modified - a.modified;
      return a.name.localeCompare(b.name);
    }
    return a.name.localeCompare(b.name);
  });
  return sorted;
}

function FilePane({ side, sortBy }: { side: Side; sortBy: SortBy }) {
  const [path, setPath] = useState("");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    listFiles(side, path).then((d) => setFiles(d.files)).catch(() => setFiles([])).finally(() => setLoading(false));
  }, [side, path]);

  useEffect(() => { load(); }, [load]);

  const sortedFiles = useMemo(() => sortFiles(files, sortBy), [files, sortBy]);

  const navigateUp = () => {
    const parts = path.split("/").filter(Boolean);
    parts.pop();
    setPath(parts.join("/"));
  };

  const navigateInto = (dirName: string) => {
    setPath(path ? `${path}/${dirName}` : dirName);
  };

  return (
    <div className={`flex-1 border-2 rounded-xl overflow-hidden ${SIDE_COLOR[side]}`}>
      <div className={`px-4 py-2 text-xs font-bold ${side === "s2" ? "bg-blue-400 text-white" : "bg-orange-400 text-white"}`}>
        {SIDE_LABEL[side]}
      </div>
      <div className="px-3 py-2 bg-white border-b flex items-center gap-2">
        <button onClick={navigateUp} disabled={!path} className="px-2 py-1 text-xs rounded bg-gray-100 hover:bg-gray-200 disabled:opacity-30">
          ..
        </button>
        <span className="text-xs font-mono text-gray-600 truncate">/{path || ""}</span>
        <button onClick={load} className="ml-auto text-xs text-gray-400 hover:text-gray-600">
          refresh
        </button>
      </div>
      <div className="bg-white overflow-y-auto" style={{ height: "calc(100% - 80px)" }}>
        {loading ? (
          <p className="p-4 text-xs text-gray-400">Loading...</p>
        ) : sortedFiles.length === 0 ? (
          <p className="p-4 text-xs text-gray-400 text-center">Empty</p>
        ) : (
          <div className="divide-y divide-gray-100">
            {sortedFiles.map((f) => (
              <div
                key={f.name}
                className={`flex items-center gap-2 px-3 py-2 text-xs hover:bg-gray-50 ${f.is_dir ? "cursor-pointer" : "cursor-grab"}`}
                draggable={!f.is_dir}
                onDragStart={(e) => {
                  if (f.is_dir) { e.preventDefault(); return; }
                  e.dataTransfer.setData("text/plain", JSON.stringify({ fileName: f.name, srcSide: side, srcPath: path }));
                  e.dataTransfer.effectAllowed = "copy";
                }}
                onClick={() => f.is_dir && navigateInto(f.name)}
              >
                <span className="text-base">{f.is_dir ? "📁" : "📄"}</span>
                <span className={`flex-1 truncate ${f.is_dir ? "font-medium text-gray-800" : "text-gray-600"}`}>
                  {f.name}
                </span>
                {!f.is_dir && <span className="text-gray-400">{formatSize(f.size)}</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function FileManager() {
  const [msg, setMsg] = useState<{ type: "ok" | "err" | "warn"; text: string } | null>(null);
  const [transferring, setTransferring] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [sortBy, setSortBy] = useState<SortBy>("modified");

  const handleDrop = async (e: React.DragEvent, targetSide: Side) => {
    e.preventDefault();
    const raw = e.dataTransfer.getData("text/plain");
    if (!raw) return;
    try {
      const { fileName, srcSide, srcPath } = JSON.parse(raw) as { fileName: string; srcSide: Side; srcPath: string };
      if (srcSide === targetSide) {
        setMsg({ type: "warn", text: "같은 영역 내 이동은 지원하지 않습니다." });
        return;
      }

      const direction = srcSide === "s2" ? "S2 → S1 (가드레일 검사)" : "S1 → S2 (통과)";
      setMsg({ type: "ok", text: `${fileName} 전송 중... (${direction})` });
      setTransferring(true);

      const result = await transferFile(fileName, srcSide, srcPath, "");
      if (result.ok) {
        setMsg({ type: "ok", text: `${fileName} 전송 완료 (${direction})` });
      } else {
        setMsg({ type: "err", text: `${fileName} 전송 차단: ${result.reason || result.error}` });
      }
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setMsg({ type: "err", text: `전송 실패: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setTransferring(false);
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h1 className="text-xl font-bold">File Manager</h1>
        <div className="flex items-center gap-3">
          <div className="inline-flex rounded-lg border border-gray-200 overflow-hidden text-xs">
            <button
              onClick={() => setSortBy("modified")}
              className={`px-3 py-1 ${sortBy === "modified" ? "bg-gray-800 text-white" : "bg-white text-gray-600 hover:bg-gray-50"}`}
            >
              최신수정순
            </button>
            <button
              onClick={() => setSortBy("name")}
              className={`px-3 py-1 border-l border-gray-200 ${sortBy === "name" ? "bg-gray-800 text-white" : "bg-white text-gray-600 hover:bg-gray-50"}`}
            >
              이름순
            </button>
          </div>
          <p className="text-xs text-gray-500">
            S2→S1 : 가드레일 검사 &nbsp;|&nbsp; S1→S2 : 통과 &nbsp;|&nbsp; 폴더 전송 불가, 파일만
          </p>
        </div>
      </div>

      {msg && (
        <div className={`mb-3 p-2 rounded-lg text-xs ${msg.type === "ok" ? "bg-green-50 text-green-700" : msg.type === "err" ? "bg-red-50 text-red-700" : "bg-yellow-50 text-yellow-700"}`}>
          {msg.text}
        </div>
      )}

      <div className="flex-1 flex gap-4 min-h-0">
        <div
          className="flex-1 flex"
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
          onDrop={(e) => handleDrop(e, "s2")}
          key={`s2-${refreshKey}`}
        >
          <FilePane side="s2" sortBy={sortBy} />
        </div>

        <div className="flex flex-col items-center justify-center gap-2 px-2">
          <div className="text-xs text-gray-400 font-medium">drag</div>
          <div className="text-2xl">⇄</div>
          <div className="text-xs text-gray-400 font-medium">drop</div>
        </div>

        <div
          className="flex-1 flex"
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
          onDrop={(e) => handleDrop(e, "s1")}
          key={`s1-${refreshKey}`}
        >
          <FilePane side="s1" sortBy={sortBy} />
        </div>
      </div>
    </div>
  );
}
