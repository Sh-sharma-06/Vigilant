"""Pure metadata analysis. Never load or execute model artifacts."""
from collections import Counter

def classify(record):
    verdict, expected = record.get('verdict'), record.get('expected', record.get('expected_label'))
    if verdict == 'ERROR': return 'ERR'
    if verdict == 'TIMEOUT': return 'TIMEOUT'
    if expected == 'MALICIOUS': return 'TP' if verdict == 'MALICIOUS' else 'FN'
    if expected == 'BENIGN':
        if verdict == 'MALICIOUS': return 'FP'
        if verdict == 'BENIGN': return 'TN'
    return 'UNKNOWN'

def compute_confusion_matrix(records):
    counts = {key: 0 for key in ('TP', 'TN', 'FP', 'FN', 'ERR', 'TIMEOUT', 'UNKNOWN')}
    for record in records: counts[classify(record)] += 1
    total = sum(counts.values()) or 1
    counts['dropout_rate'] = round((counts['ERR'] + counts['TIMEOUT']) / total, 4)
    return counts

def cluster_failure_signatures(records):
    counts = Counter()
    for record in records:
        outcome = classify(record)
        if outcome not in ('FP', 'FN'): continue
        features = record.get('features') or {}
        tokens = set(features.get('globals', []) + features.get('stack_globals', []))
        for token in tokens or {'archive / unknown signature'}: counts[outcome, token] += 1
    return [dict(outcome=outcome, token=token, count=count, recommendation=(
        'Review safe import context before adjusting the allowlist.' if outcome == 'FP'
        else 'Review execution traces and add a targeted detection signature.'))
        for (outcome, token), count in counts.most_common()]
