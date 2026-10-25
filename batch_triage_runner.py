#!/usr/bin/env python3
"""Hash, assign deterministic dev/test split, sanitize hostile strings, and evaluate models."""
import argparse
import hashlib
import html
import importlib
import io
import json
import multiprocessing as mp
import os
from pathlib import Path
import pickletools
import subprocess
import time
import zipfile

from container_dispatcher import strip_zip_encryption_bits
from inspectors.multi_format_scanner import identify_format

MAX_STATIC_BYTES = 32 * 1024 * 1024
MAX_STRING_LEN = 160
MAX_TOKEN_LIST = 100

SUPPORTED_EXTENSIONS = {
    '.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.joblib', '.npz',
    '.zip', '.7z', '.onnx', '.h5', '.keras', '.gguf', '.safetensors'
}

def sanitize_hostile_str(val: str, max_len: int = MAX_STRING_LEN) -> str:
    """Treat all model strings/class names as hostile attacker input."""
    if not isinstance(val, str):
        val = str(val)
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in val[:max_len])
    return html.escape(cleaned, quote=True)

def assign_deterministic_split(sample_id: str) -> str:
    """Deterministic 80% dev / 20% test split locked by SHA-256 hash."""
    return "test" if (int(sample_id[:8], 16) % 5 == 0) else "dev"

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def get_detonator():
    try:
        candidate = getattr(importlib.import_module('container_dispatcher'), 'detonate_in_container')
        if callable(candidate):
            return candidate
    except (ImportError, AttributeError):
        pass
    return None

def profile_pickle(payload):
    counts, globals_, stack_globals, strings, memo = {}, [], [], [], {}
    partial = None
    try:
        for op, arg, pos in pickletools.genops(payload):
            counts[op.name] = counts.get(op.name, 0) + 1
            if op.name == 'GLOBAL':
                globals_.append(sanitize_hostile_str(str(arg).replace(' ', '.')))
            if op.name in ('UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8'):
                strings.append(str(arg)[:MAX_STRING_LEN])
            elif op.name in ('BINPUT', 'LONG_BINPUT', 'PUT') and strings:
                try:
                    memo[int(arg)] = strings[-1]
                except Exception:
                    pass
            elif op.name == 'MEMOIZE' and strings:
                memo[len(memo)] = strings[-1]
            elif op.name in ('BINGET', 'LONG_BINGET', 'GET'):
                try:
                    if int(arg) in memo:
                        strings.append(memo[int(arg)])
                except Exception:
                    pass
            elif op.name == 'STACK_GLOBAL' and len(strings) >= 2:
                stack_globals.append(sanitize_hostile_str('.'.join(strings[-2:])))
                strings = []
    except Exception as exc:
        partial = type(exc).__name__
    return dict(
        globals=sorted(set(globals_))[:MAX_TOKEN_LIST],
        stack_globals=sorted(set(stack_globals))[:MAX_TOKEN_LIST],
        op_counts=counts,
        partial_parse_error=partial,
    )

def extract_features(path: Path):
    features = dict(
        total_size_bytes=path.stat().st_size,
        globals=[],
        stack_globals=[],
        op_counts={},
        extraction_notes=[],
    )
    payloads = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                budget = MAX_STATIC_BYTES
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if info.file_size > budget:
                        features['extraction_notes'].append('Static extraction budget exceeded')
                        continue
                    try:
                        with archive.open(info) as stream:
                            payloads.append(stream.read(info.file_size))
                    except RuntimeError as re_err:
                        if "encrypted" in str(re_err).lower() or "password" in str(re_err).lower():
                            raw_bytes = path.read_bytes()
                            stripped = strip_zip_encryption_bits(raw_bytes)
                            try:
                                with zipfile.ZipFile(io.BytesIO(stripped), 'r') as sz:
                                    payloads.append(sz.read(info.filename))
                                features['extraction_notes'].append('Spoofed ZIP encryption bit stripped in memory.')
                            except Exception:
                                features['extraction_notes'].append('Password-protected archive member skipped.')
                        else:
                            features['extraction_notes'].append(f'Archive read warning: {type(re_err).__name__}')
                    budget -= info.file_size
            features['archive_format'] = 'zip'
        elif path.suffix.lower() == '.7z':
            features['archive_format'] = '7z'
            features['extraction_notes'].append('7z static opcode extraction delegated to dispatcher.')
        else:
            with open(path, 'rb') as stream:
                payloads.append(stream.read(MAX_STATIC_BYTES))
    except Exception as exc:
        features['extraction_notes'].append(f'Archive structural anomaly: {type(exc).__name__}')

    for payload in payloads:
        result = profile_pickle(payload)
        features['globals'].extend(result['globals'])
        features['stack_globals'].extend(result['stack_globals'])
        for op, count in result['op_counts'].items():
            features['op_counts'][op] = features['op_counts'].get(op, 0) + count
        if result['partial_parse_error']:
            features['extraction_notes'].append('Partial pickle profile: ' + sanitize_hostile_str(result['partial_parse_error']))

    features['globals'] = sorted(set(features['globals']))[:MAX_TOKEN_LIST]
    features['stack_globals'] = sorted(set(features['stack_globals']))[:MAX_TOKEN_LIST]
    return features

def _worker(path, pipe):
    try:
        detonator = get_detonator()
        if detonator is None:
            raise RuntimeError('Docker dispatcher unavailable; no model was executed.')
        result = detonator(path)
        if not isinstance(result, dict):
            raise TypeError('Dispatcher must return a verdict dictionary.')
        if 'confidence' not in result:
            result['confidence'] = 'HIGH'
        if 'error' not in result:
            result['error'] = None
        pipe.send(result)
    except Exception as exc:
        pipe.send(dict(verdict='ERROR', confidence='LOW', summary=sanitize_hostile_str(str(exc)), error=type(exc).__name__))
    finally:
        pipe.close()

def detonate(path, timeout):
    ctx = mp.get_context('spawn')
    receive, send = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_worker, args=(str(path.resolve()), send))
    process.start()
    send.close()
    try:
        if receive.poll(timeout):
            try:
                return receive.recv()
            except EOFError:
                return dict(verdict='ERROR', confidence='LOW', summary='Dispatcher exited without telemetry.', error='DispatcherCrash')
        return dict(verdict='TIMEOUT', confidence='LOW', summary=f'Dispatcher exceeded {timeout:.1f}s.', error='TimeoutError')
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join()
        receive.close()

def infer_expected_label(filename: str, cli_expected: str) -> str:
    if cli_expected != 'AUTO':
        return cli_expected
    fname = filename.lower()
    if any(fname.startswith(p) for p in ('malicious', 'bad_', 'pytorch_magic', 'sys_module')):
        return 'MALICIOUS'
    return 'BENIGN'

def infer_provenance(filename: str, cli_prov: str) -> str:
    if cli_prov != 'auto':
        return cli_prov
    fname = filename.lower()
    if fname.startswith('malhug_'):
        return 'in-the-wild'
    if fname.startswith('hf_'):
        return 'hf-production'
    if any(fname.startswith(p) for p in ('malicious_', 'benign_')):
        return 'scanner-fixture'
    return 'own-synthetic'

def evaluate(path: Path, expected: str, provenance: str, commit: str, timeout: float):
    started = time.monotonic()
    sample_id = sha256_file(path)
    split = assign_deterministic_split(sample_id)
    resolved_expected = infer_expected_label(path.name, expected)
    resolved_prov = infer_provenance(path.name, provenance)
    true_fmt = identify_format(str(path))

    record = dict(
        sample_id=sample_id,
        model_name=sanitize_hostile_str(path.name, 120),
        format=true_fmt,
        split=split,
        provenance=resolved_prov,
        git_commit=commit,
        expected=resolved_expected,
        verdict='ERROR',
        confidence='LOW',
        summary='',
        error=None,
        features={'total_size_bytes': path.stat().st_size},
    )
    try:
        record['features'] = extract_features(path)
        result = detonate(path, timeout)
        if result.get('verdict') not in ('MALICIOUS', 'BENIGN', 'SUSPICIOUS', 'ERROR', 'TIMEOUT'):
            raise ValueError(f"Invalid dispatcher verdict: {result.get('verdict')}")
        record['verdict'] = result['verdict']
        record['confidence'] = result.get('confidence', 'HIGH') if result.get('confidence') in ('HIGH', 'MEDIUM', 'LOW') else 'HIGH'
        record['summary'] = sanitize_hostile_str(result.get('summary', ''), 280)
        record['error'] = sanitize_hostile_str(result['error'], 120) if result.get('error') else None
    except Exception as exc:
        record.update(verdict='ERROR', summary=sanitize_hostile_str(str(exc), 200), error=type(exc).__name__)
    record['latency_s'] = round(time.monotonic() - started, 6)
    return record

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--expected', choices=['BENIGN', 'MALICIOUS', 'UNKNOWN', 'AUTO'], default='AUTO')
    parser.add_argument('--provenance', choices=['auto', 'in-the-wild', 'hf-production', 'scanner-fixture', 'own-synthetic', 'red-team'], default='auto')
    parser.add_argument('--output', type=Path, default=Path('telemetry.jsonl'))
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    if not args.directory.is_dir():
        parser.error('directory must exist')
    try:
        commit = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        commit = 'unknown'

    seen = set()
    if args.resume and args.output.exists():
        for line in args.output.read_text().splitlines():
            try:
                seen.add(json.loads(line)['sample_id'])
            except (ValueError, KeyError):
                pass

    paths = sorted(
        p for p in args.directory.rglob('*')
        if p.is_file() and p.name != 'manifest.json' and p.suffix.lower() in SUPPORTED_EXTENSIONS
    )
    with args.output.open('a' if args.resume else 'w') as out:
        for path in paths:
            try:
                if args.resume and sha256_file(path) in seen:
                    continue
                record = evaluate(path, args.expected, args.provenance, commit, args.timeout)
                out.write(json.dumps(record) + '\n')
                out.flush()
                os.fsync(out.fileno())
                print(f"[{record['split'].upper():4}] {record['verdict']:10} | {record['format']:11} | {record['provenance']:15} | {path.name}")
            except OSError as exc:
                print(f'Cannot read {path.name}: {type(exc).__name__}')

if __name__ == '__main__':
    main()
