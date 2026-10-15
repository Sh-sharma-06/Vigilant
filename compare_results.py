#!/usr/bin/env python3
"""compare_results.py - what changed for Vigilant between two benchmark runs?

  python3 compare_results.py results_raw.csv results_raw_vigilant.csv

Prints, for vigilant_strict and vigilant_lenient: files now caught, files now
missed, new false positives, fixed false positives, plus the new totals.
"""
import csv
import sys

old_path, new_path = sys.argv[1], sys.argv[2]


def load(path):
    rows = {}
    for r in csv.DictReader(open(path)):
        if r["tool"].startswith("vigilant"):
            rows[(r["tool"], r["file"])] = r
    return rows


old, new = load(old_path), load(new_path)
for tool in ("vigilant_strict", "vigilant_lenient"):
    keys = sorted(k for k in new if k[0] == tool)
    caught, missed, new_fp, fixed_fp = [], [], [], []
    for k in keys:
        n, o = new[k], old.get(k)
        if o is None or n["label"] not in ("malicious", "benign"):
            continue
        nf, of = n["flagged"] == "True", o["flagged"] == "True"
        if n["label"] == "malicious":
            (caught if nf and not of else missed if of and not nf else []).append(k[1])
        else:
            (new_fp if nf and not of else fixed_fp if of and not nf else []).append(k[1])
    mal = [new[k] for k in keys if new[k]["label"] == "malicious"]
    ben = [new[k] for k in keys if new[k]["label"] == "benign"]
    tp = sum(r["flagged"] == "True" for r in mal)
    fp = sum(r["flagged"] == "True" for r in ben)
    print(f"\n=== {tool} ===")
    print(f"recall {tp}/{len(mal)} = {tp / max(len(mal), 1):.1%}   false positives {fp}/{len(ben)} = {fp / max(len(ben), 1):.1%}")
    for title, items in (("now CAUGHT", caught), ("now MISSED (regression!)", missed),
                         ("NEW false positives", new_fp), ("false positives FIXED", fixed_fp)):
        print(f"  {title}: {len(items)}")
        for f in items:
            print(f"      {f}")
