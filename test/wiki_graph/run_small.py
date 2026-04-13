#!/usr/bin/env python3
"""소규모 실험 (20건 × 3사) — 진짜 LLM skill 검증용."""
import json, os, subprocess, sys
from collections import Counter
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"
PROXY = "http://localhost:19080"
JAR = "/tmp/ssc.jar"

def curl_json(method, path, body=None):
    args = ["curl", "-s", "-X", method, f"{PROXY}{path}", "-b", JAR]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body, ensure_ascii=False)]
    res = subprocess.run(args, capture_output=True, text=True, timeout=120)
    try:
        return json.loads(res.stdout)
    except Exception:
        return {"_raw": res.stdout[:300]}

def reset():
    nodes = curl_json("GET", "/api/wiki-graph/nodes") or []
    for n in nodes:
        curl_json("DELETE", f"/api/wiki-graph/nodes/{n['id']}")
    edges = curl_json("GET", "/api/wiki-graph/edges") or []
    for e in edges:
        curl_json("DELETE", f"/api/wiki-graph/edges/{e['id']}")

def run(company, n=20):
    print(f"\n══ {company} ══")
    reset()
    samples = [json.loads(l) for l in (FIX/f"{company}.jsonl").read_text(encoding="utf-8").splitlines()]
    # deny 만 선별 + n건.
    deny_samples = [s for s in samples if s["decision"] == "deny"][:n]
    print(f"  feeding {len(deny_samples)} deny samples via LLM skill...")

    action_counts = Counter()
    errors = 0
    for i, s in enumerate(deny_samples):
        res = curl_json("POST", "/api/wiki-graph/skill/wiki_edit", {
            "input": s["input"],
            "decision": "deny",
            "reason": s.get("reason", ""),
        })
        if "error" in res and "_raw" not in res:
            errors += 1
            if errors <= 3:
                print(f"  err [{i}]: {res['error'][:100]}")
        else:
            action_counts["created"] += len(res.get("nodes_created") or [])
            action_counts["updated"] += len(res.get("nodes_updated") or [])
            action_counts["edges"] += len(res.get("edges_created") or [])
            action_counts["errs"] += len(res.get("errors") or [])
        if (i+1) % 5 == 0:
            print(f"  progress {i+1}/{len(deny_samples)}")

    nodes = curl_json("GET", "/api/wiki-graph/nodes") or []
    edges = curl_json("GET", "/api/wiki-graph/edges") or []
    print(f"\n  결과:")
    print(f"    samples processed: {len(deny_samples)} (errors: {errors})")
    print(f"    actions aggregated: {dict(action_counts)}")
    print(f"    final nodes: {len(nodes)}, edges: {len(edges)}")
    print(f"  생성된 노드 (상위 10개):")
    for n in nodes[:10]:
        print(f"    [{n['id']}] {n['definition'][:40]} tags={n.get('tags',[])}")
    if len(nodes) > 10:
        print(f"    ... +{len(nodes)-10}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    if target == "all":
        for c in ["logistics", "mathbook", "aisec"]:
            run(c, n)
    else:
        run(target, n)
