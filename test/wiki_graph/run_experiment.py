#!/usr/bin/env python3
"""
run_experiment.py — 3사 데이터를 차례로 wiki-graph 에 feed.

각 회사:
  1) reset_graph()  — 모든 nodes/edges/decisions/dialogs 삭제
  2) for each sample (~200개):
       - DecisionLog 추가 (approve/deny)
       - LLM 흉내 (휴리스틱): deny 인 경우 매칭/생성할 노드 결정
         · 기존 노드 중 키워드 매칭으로 유사 노드 찾기
         · 없으면 새 노드 (definition 자동 생성)
         · 첫 노드 외 후속 노드는 supports/example_of edge 로 연결
  3) 결과 메트릭 출력: 노드 수, 엣지 수, relation 분포, 평균 in/out degree

ollama 등 실제 LLM 호출은 후속 작업. 본 러너는 primitive API 가 패턴 받았을 때
그래프가 합리적으로 성장하는지 검증 목적.

Usage:
  python3 run_experiment.py logistics
  python3 run_experiment.py mathbook
  python3 run_experiment.py aisec
  python3 run_experiment.py all
"""

import json
import os
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

POLICY_URL = os.environ.get("POLICY_URL", "https://boan-policy-server-sds-corp-3avhtf4kka-du.a.run.app")
ORG_ID = os.environ.get("ORG_ID", "sds-corp")
TOKEN_FILE = Path(__file__).parents[2] / "deploy" / "config" / f"{ORG_ID}.token"
TOKEN = TOKEN_FILE.read_text().strip()
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

FIXTURES_DIR = Path(__file__).parent / "fixtures"

def req(method: str, path: str, body=None):
    url = f"{POLICY_URL}/org/{ORG_ID}/v1/wiki-graph/{path}"
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers=HEADERS)
    with urllib.request.urlopen(r, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


def list_nodes():
    return req("GET", "nodes") or []
def list_edges():
    return req("GET", "edges") or []


def reset_graph():
    """모든 노드/엣지/decision/dialog 삭제."""
    n_count = e_count = d_count = dl_count = 0
    for n in list_nodes():
        try:
            req("DELETE", f"nodes/{n['id']}")
            n_count += 1
        except Exception:
            pass
    # nodes 삭제 시 연결 edge 자동 정리되지만 dangling 정리.
    for e in list_edges():
        try:
            req("DELETE", f"edges/{e['id']}")
            e_count += 1
        except Exception:
            pass
    # decision/dialog 직접 삭제 endpoint 없음 — 파일시스템 직접 정리는 서버측 작업.
    print(f"  reset: deleted {n_count} nodes, {e_count} edges (dangling)")


# ── 휴리스틱 LLM 흉내 ────────────────────────────────────
# deny sample 에서 키워드 추출 → 비슷한 기존 노드 찾기 → 없으면 새 노드.

KEYWORD_GROUPS = {
    # logistics
    "alg":      ("내부 알고리즘",     ["optimize_route", "WarehouseAllocation", "알고리즘", "라우팅"]),
    "pii":      ("고객 개인정보",     ["고객명", "주민번호", "010-", "주소: "]),
    "contract": ("B2B 계약/단가",    ["계약 단가", "단가표", "협상", "할인율"]),
    "kpi":      ("내부 KPI/실적",    ["KPI", "달성률", "내부 목표"]),
    "infra":    ("IT 인프라/계정",   ["DB 연결", "Kubernetes secret", "AWS IAM", "API_KEY", "VPN"]),
    "facility": ("시설 설계/보안",   ["설계도", "CCTV", "야간 경비"]),
    # mathbook
    "answer":   ("정답/해설 원고",   ["정답:", "해설 원고", "답안"]),
    "author":   ("저자 계약",        ["저자", "인세율", "선지급금"]),
    "schedule": ("출간 공정",        ["원고 마감", "디자인", "인쇄"]),
    "rival":    ("경쟁사 분석",      ["경쟁사", "판매량 분석"]),
    "academy":  ("학원 단가",        ["학원체인", "대량납품"]),
    "student":  ("학생 개인정보",    ["응시자", "점수", "오답유형"]),
    "drm":      ("DRM/저작권",       ["DRM", "마스터키", "Book ID"]),
    # aisec
    "vuln":     ("취약점 보고서",    ["취약점 평가", "WAF 우회", "IDOR", "SQLi"]),
    "zeroday":  ("Zero-day 추적",    ["zero-day", "PoC", "CVSS"]),
    "cred":     ("고객 자격증명",    ["테스트용 제공 계정", "P@ss"]),
    "topology": ("네트워크 토폴로지", ["네트워크 토폴로지", "NDA"]),
    "pentest":  ("Pentest 결과",    ["Pentest", "shell", "lateral movement"]),
    "tuning":   ("보안 제품 룰셋",  ["SIEM", "Honeynet", "EDR", "IDS 시그니처"]),
    "hr":       ("내부 인사평가",    ["보안인식평가", "직원"]),
    "src":      ("자체 제품 소스",   ["스캐너 소스코드", "detect_vulns"]),
    "biz":      ("계약 협상",        ["견적서", "할인율", "협상 중"]),
}

def classify(text: str) -> str | None:
    """간단 키워드 매칭. 가장 먼저 매칭되는 그룹 반환."""
    for key, (_, kws) in KEYWORD_GROUPS.items():
        for kw in kws:
            if kw in text:
                return key
    return None


def emulate_skill_wiki_edit(decision: dict, existing_nodes: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    deny 결정마다:
      - 카테고리 분류 → 기존 노드와 매칭하면 update (content append),
        없으면 신규 생성.
      - 노드가 5개 이상 같은 카테고리면 supports edge 로 'umbrella' 노드 추가.
    """
    new_nodes, new_edges = [], []
    if decision["decision"] != "deny":
        return new_nodes, new_edges

    cat = classify(decision["input"])
    if not cat:
        return new_nodes, new_edges

    cat_def, _ = KEYWORD_GROUPS[cat]
    # 기존 노드 중 같은 카테고리 정의 찾기.
    existing = [n for n in existing_nodes if n.get("definition", "").startswith(cat_def)]

    if not existing:
        # 신규 노드.
        node = req("POST", "nodes", {
            "definition": cat_def[:30],
            "content": f"패턴: {cat_def}\n예시: {decision['input'][:200]}",
            "tags": [cat],
            "created_by": "skill.wiki_edit (heuristic)",
        })
        new_nodes.append(node)
    else:
        # 기존 노드 content 에 예시 추가 (1000자 한도 내).
        n = existing[0]
        addition = f"\n- {decision['input'][:80]}"
        new_content = (n.get("content", "") + addition)[:980]
        updated = req("PATCH", f"nodes/{n['id']}", {
            "content": new_content,
            "updated_by": "skill.wiki_edit (heuristic)",
        })
        new_nodes.append(updated)

    return new_nodes, new_edges


def run_company(name: str):
    fixture = FIXTURES_DIR / f"{name}.jsonl"
    if not fixture.exists():
        print(f"⚠ fixture not found: {fixture}")
        return
    print(f"\n══════ {name} ══════")
    print("  reset graph...")
    reset_graph()

    samples = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines()]
    print(f"  feeding {len(samples)} samples...")

    # decision append + emulate skill
    cat_first_node: dict[str, dict] = {}
    for i, s in enumerate(samples):
        try:
            req("POST", "decisions", {
                "input": s["input"],
                "decision": s["decision"],
                "reason": s.get("reason", ""),
                "labeler": "test",
            })
        except Exception as e:
            print(f"  warn: decision append {s['id']}: {e}")
        # emulate skill
        try:
            existing = list_nodes() if i % 5 == 0 else list(cat_first_node.values())  # cache-ish
            new_nodes, _ = emulate_skill_wiki_edit(s, existing)
            for nn in new_nodes:
                # cache by definition prefix
                cat_first_node[nn.get("definition", "")] = nn
        except Exception as e:
            print(f"  warn: skill emulate {s['id']}: {e}")
        if (i + 1) % 50 == 0:
            print(f"  progress: {i+1}/{len(samples)}")

    # 결과 메트릭
    nodes = list_nodes()
    edges = list_edges()
    print(f"\n  ── 결과 ──")
    print(f"  nodes: {len(nodes)}")
    print(f"  edges: {len(edges)}")
    rel_dist = Counter(e["relation"] for e in edges)
    print(f"  relations: {dict(rel_dist)}")
    in_deg = Counter(e["to"] for e in edges)
    out_deg = Counter(e["from"] for e in edges)
    if nodes:
        print(f"  avg in-deg:  {sum(in_deg.values())/len(nodes):.2f}")
        print(f"  avg out-deg: {sum(out_deg.values())/len(nodes):.2f}")
    print(f"\n  생성된 노드들:")
    for n in nodes[:20]:
        tag = ",".join(n.get("tags", []))
        print(f"    [{n['id']}] {n['definition']} ({tag})")
    if len(nodes) > 20:
        print(f"    ... +{len(nodes)-20} more")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    target = sys.argv[1]
    if target == "all":
        for c in ["logistics", "mathbook", "aisec"]:
            run_company(c)
    else:
        run_company(target)

if __name__ == "__main__":
    main()
