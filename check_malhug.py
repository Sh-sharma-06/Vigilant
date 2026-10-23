import json
raw = open("malhug_results.json", "rb").read()
enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
rows = json.loads(raw.decode(enc))
tp = fn = fp = tn = 0
for r in rows:
    bad = r["model_name"].startswith("malhug_")
    flagged = r["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    tp += bad and flagged; fn += bad and not flagged
    fp += (not bad) and flagged; tn += (not bad) and not flagged
    print(f'{r["verdict"]:<11} {r["model_name"]:<45} {r.get("attack_vector","-")}')
print(f"\nTP={tp} FN={fn} FP={fp} TN={tn}")
if tp + fn: print(f"Recall = {tp/(tp+fn):.0%}")
if fp + tn: print(f"False-positive rate = {fp/(fp+tn):.0%}")