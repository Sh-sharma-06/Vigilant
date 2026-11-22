"""Pure metadata analysis with Split, Format, and Provenance breakdowns."""
from collections import Counter, defaultdict

def classify(record):
    verdict = record.get('verdict')
    expected = record.get('expected', record.get('expected_label'))
    if verdict == 'ERROR': return 'ERR'
    if verdict == 'TIMEOUT': return 'TIMEOUT'
    if expected == 'MALICIOUS': return 'TP' if verdict in ('MALICIOUS', 'SUSPICIOUS') else 'FN'
    if expected == 'BENIGN':
        if verdict in ('MALICIOUS', 'SUSPICIOUS'): return 'FP'
        if verdict == 'BENIGN': return 'TN'
    return 'UNKNOWN'

def compute_confusion_matrix(records):
    counts = {key: 0 for key in ('TP', 'TN', 'FP', 'FN', 'ERR', 'TIMEOUT', 'UNKNOWN')}
    for record in records:
        counts[classify(record)] += 1
    total = sum(counts.values()) or 1
    tp, tn, fp, fn = counts['TP'], counts['TN'], counts['FP'], counts['FN']
    counts['recall'] = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    counts['fpr'] = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    counts['dropout_rate'] = round((counts['ERR'] + counts['TIMEOUT']) / total, 4)
    return counts

def compute_stratified_metrics(records):
    """Breaks metrics down by split (dev vs test), format, and provenance."""
    by_split = defaultdict(list)
    by_format = defaultdict(list)
    by_prov = defaultdict(list)

    for r in records:
        by_split[r.get('split', 'unknown')].append(r)
        by_format[r.get('format', 'UNKNOWN')].append(r)
        by_prov[r.get('provenance', 'unknown')].append(r)

    return {
        "overall": compute_confusion_matrix(records),
        "by_split": {k: compute_confusion_matrix(v) for k, v in by_split.items()},
        "by_format": {k: compute_confusion_matrix(v) for k, v in by_format.items()},
        "by_provenance": {k: compute_confusion_matrix(v) for k, v in by_prov.items()},
    }

def cluster_failure_signatures(records, split_filter="dev"):
    """Only cluster failure signatures on the DEV split so TEST remains untouched!"""
    counts = Counter()
    for record in records:
        if split_filter and record.get('split') != split_filter:
            continue
        outcome = classify(record)
        if outcome not in ('FP', 'FN'):
            continue
        features = record.get('features') or {}
        tokens = set(features.get('globals', []) + features.get('stack_globals', []))
        for token in tokens or {'archive / structural signature'}:
            counts[outcome, token] += 1
    return [
        dict(
            outcome=outcome,
            token=token,
            count=count,
            recommendation=(
                'Review safe import context on DEV split before adjusting allowlist.'
                if outcome == 'FP'
                else 'Inspect DEV execution trace and add targeted rule.'
            ),
        )
        for (outcome, token), count in counts.most_common()
    ]
