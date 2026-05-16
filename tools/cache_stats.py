#!/usr/bin/env python3
"""Measure cache hit rates for build and reference trace caches."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def count_cache_entries(cache_root: Path, subdir: str) -> int:
    p = cache_root / subdir
    if not p.exists():
        return 0
    return sum(1 for d in p.iterdir() if d.is_dir() and (d / "build-info.json").exists() or (d / "canonical-trace.json").exists())


def compute_hit_rate(total_requests: int, hits: int) -> float:
    if total_requests == 0:
        return 0.0
    return (hits / total_requests) * 100


def main():
    parser = argparse.ArgumentParser(description="Cache statistics and hit rate verification")
    parser.add_argument("--cache-root", default="artifacts/cache")
    parser.add_argument("--requests-file", help="JSONL file with cache request logs")
    parser.add_argument("--verify", action="store_true", help="Verify >90% hit rate (hard requirement)")
    args = parser.parse_args()

    cache_root = Path(args.cache_root)
    build_entries = count_cache_entries(cache_root, "build")
    trace_entries = count_cache_entries(cache_root, "reference-trace")

    print(f"Build cache entries: {build_entries}")
    print(f"Reference trace cache entries: {trace_entries}")

    if args.requests_file:
        requests_path = Path(args.requests_file)
        if requests_path.exists():
            build_total = 0
            build_hits = 0
            trace_total = 0
            trace_hits = 0
            for line in requests_path.read_text().strip().splitlines():
                if not line.strip():
                    continue
                req = json.loads(line)
                kind = req.get("kind", "")
                if kind == "build":
                    build_total += 1
                    if req.get("hit"):
                        build_hits += 1
                elif kind == "reference_trace":
                    trace_total += 1
                    if req.get("hit"):
                        trace_hits += 1

            build_rate = compute_hit_rate(build_total, build_hits)
            trace_rate = compute_hit_rate(trace_total, trace_hits)

            print(f"Build cache hit rate: {build_rate:.1f}% ({build_hits}/{build_total})")
            print(f"Reference trace cache hit rate: {trace_rate:.1f}% ({trace_hits}/{trace_total})")

            if args.verify:
                if build_rate < 90.0:
                    print(f"FAIL: Build cache hit rate {build_rate:.1f}% is below 90% hard requirement")
                    return 1
                if trace_rate < 90.0:
                    print(f"FAIL: Reference trace cache hit rate {trace_rate:.1f}% is below 90% hard requirement")
                    return 1
                print("PASS: Both caches meet >90% hit rate requirement")
    else:
        print(f"Build cache total entries: {build_entries}")
        print(f"Reference trace cache total entries: {trace_entries}")


if __name__ == "__main__":
    main()
