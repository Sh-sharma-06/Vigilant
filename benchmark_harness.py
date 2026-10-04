#!/usr/bin/env python3
import csv, json, math, subprocess, sys, time
from collections import defaultdict

TIMEOUT = 300  # seconds per file


def v_picklescan(rc, out, err):
    return rc == 1

def v_modelscan(rc, out, err):
    return rc == 1

def v_fickling(rc, out, err):
    return rc == 1

def v_vigilant(rc, out, err):
    # PLACEHOLDER: adapt to your pipeline's output.
    try:
        return json.loads(out).get("verdict", "").lower() in ("malicious", "blocked")
    except Exception:
        return rc != 0


TOOLS = {
    "picklescan": (lambda f: ["picklescan", "-p", f], v_picklescan),
    "modelscan":  (lambda f: ["modelscan", "-p", f], v_modelscan),
    "fickling":   (lambda f: ["fickling", "--check-safety", f], v_fickling),
    "vigilant":   (lambda f: ["python3", "test_pipeline.py", f], v_vigilant),
}



def _vig(out):
    for line in out.splitlines():
        if line.startswith("VIGILANT_RESULT:"):
            try:
                return json.loads(line.split(":", 1)[1]).get("verdict", "").upper()
            except Exception:
                return ""
    return ""

def v_vig_strict(rc, out, err):
    return _vig(out) in ("SUSPICIOUS", "MALICIOUS")

def v_vig_lenient(rc, out, err):
    return _vig(out) == "MALICIOUS"

VIG = lambda f: ["./venv/bin/python", "vigilant_one.py", f]
TOOLS = {
    "picklescan": (lambda f: ["picklescan", "-p", f], v_picklescan),
    "modelscan":  (lambda f: ["modelscan", "-p", f], v_modelscan),
    "fickling":   (lambda f: ["fickling", "--check-safety", f], v_fickling),
    "vigilant_strict":  (VIG, v_vig_strict),
    "vigilant_lenient": (VIG, v_vig_lenient),
}

def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, (c + m) / d)


def fmt(k, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {k/n:.1%} (CI {lo:.1%}-{hi:.1%})"


def main(labels_path):
    with open(labels_path) as f:
        rows = list(csv.DictReader(f))

    raw = []
    for tool, (cmd, verdict) in TOOLS.items():
        for r in rows:
            start = time.time()
            try:
                p = subprocess.run(cmd(r["file"]), capture_output=True, text=True, timeout=TIMEOUT)
                rc, out, err, timed_out = p.returncode, p.stdout, p.stderr, False
            except subprocess.TimeoutExpired:
                rc, out, err, timed_out = -1, "", "TIMEOUT", True
            except FileNotFoundError as e:
                rc, out, err, timed_out = -2, "", str(e), True
            elapsed = time.time() - start
            flagged = False if timed_out else verdict(rc, out, err)
            raw.append({
                "tool": tool, "file": r["file"], "label": r["label"],
                "category": r.get("category", ""), "flagged": flagged,
                "exit_code": rc, "seconds": round(elapsed, 3),
                "error": timed_out or (rc not in (0, 1) and not tool.startswith("vigilant")), "stderr": err.strip()[:300].replace("\n", " "),
            })
            print(f"{tool:11s} {r['file']}: flagged={flagged} rc={rc} {elapsed:.2f}s")

    with open("results_raw.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(raw[0].keys()))
        w.writeheader()
        w.writerows(raw)

    summary = []
    for tool in TOOLS:
        rs = [x for x in raw if x["tool"] == tool]
        mal = [x for x in rs if x["label"] == "malicious"]
        ben = [x for x in rs if x["label"] == "benign"]
        tp = sum(x["flagged"] for x in mal)
        fn = len(mal) - tp
        fp = sum(x["flagged"] for x in ben)
        tn = len(ben) - fp
        times = sorted(x["seconds"] for x in rs)
        med = times[len(times) // 2] if times else 0
        errs = sum(x["error"] for x in rs)
        prec = f"{tp/(tp+fp):.1%}" if (tp + fp) else "n/a"
        summary.append({
            "tool": tool, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "recall": fmt(tp, tp + fn), "FPR": fmt(fp, fp + tn),
            "precision": prec, "median_sec": med, "errors_or_timeouts": errs,
        })
        cats = defaultdict(lambda: [0, 0])
        for x in mal:
            cats[x["category"]][1] += 1
            cats[x["category"]][0] += int(x["flagged"])
        for c, (k, n) in sorted(cats.items()):
            print(f"  [{tool}] {c}: {fmt(k, n)}")

    with open("results_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)

    print("\n=== SUMMARY ===")
    for s in summary:
        print(s)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: benchmark_harness.py labels.csv")
    main(sys.argv[1])
