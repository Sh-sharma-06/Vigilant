"""
hf_source_unsafe.py — finds models Hugging Face's own PickleScan already
flagged as unsafe/suspicious, for the Vigilant eval dataset.

This only touches models Hugging Face itself has already scanned and
already labeled unsafe on their own Hub — it doesn't write or generate any
exploit code, just finds and (optionally) downloads already-flagged files.

Usage:
    export HF_TOKEN=hf_xxx          # optional, raises your rate limit
    python3 hf_source_unsafe.py --limit 100 --out sourced_unsafe

    # once the manifest looks right, actually pull the flagged files down:
    python3 hf_source_unsafe.py --limit 100 --out sourced_unsafe --download

HF has no single "list every unsafe model" filter, so this checks a batch
of candidate repos one at a time against HF's own per-repo scan endpoint
(https://huggingface.co/api/models/{repo_id}/scan), which I confirmed
exists and returns a boolean "hasUnsafeFile". I could not fetch a live
example of its full JSON shape from here, so the first few repos checked
have their raw response printed — check that unsafe_files_from_scan() is
actually finding real filenames there before trusting this at scale.
"""

import argparse
import json
import os
import time
from pathlib import Path

import requests
from huggingface_hub import HfApi, hf_hub_download

HF_SCAN_URL = "https://huggingface.co/api/models/{repo_id}/scan"


def list_candidates(limit, library, token=None):
    api = HfApi(token=token)
    kwargs = dict(sort="lastModified", direction=-1, limit=limit)
    if library:
        try:
            models = list(api.list_models(library=library, **kwargs))
        except TypeError:
            models = list(api.list_models(filter=library, **kwargs))
    else:
        models = list(api.list_models(**kwargs))
    return [m.id for m in models]


def scan_repo(repo_id, token=None, session=None):
    session = session or requests.Session()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = HF_SCAN_URL.format(repo_id=repo_id)
    try:
        resp = session.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"    [!] request failed for {repo_id}: {e}")
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def unsafe_files_from_scan(scan):
    """Best-effort extraction of which files were flagged. HF's exact field
    names here are unconfirmed from this environment — tries a few likely
    shapes and falls back to a placeholder so it's obvious when it hasn't
    actually found real filenames."""
    if not scan or not scan.get("hasUnsafeFile"):
        return []
    for key in ("filesWithUnsafeImports", "files", "scans", "scansByRepoFile"):
        files = scan.get(key)
        if isinstance(files, list):
            names = [
                f.get("path") or f.get("filename") or f.get("name")
                for f in files
                if isinstance(f, dict) and (f.get("hasUnsafeImports") or f.get("unsafe") or f.get("hasUnsafeImport"))
            ]
            names = [n for n in names if n]
            if names:
                return names
        if isinstance(files, dict):
            names = [
                fname for fname, info in files.items()
                if isinstance(info, dict) and (info.get("hasUnsafeImports") or info.get("unsafe"))
            ]
            if names:
                return names
    return ["<hasUnsafeFile=true but filename not found in expected fields — check raw JSON above>"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50, help="how many candidate repos to check")
    ap.add_argument("--library", default="pytorch", help="library filter for candidates, empty string for none")
    ap.add_argument("--out", default="sourced_unsafe", help="output directory")
    ap.add_argument("--debug-first", type=int, default=3, help="print raw scan JSON for the first N repos checked")
    ap.add_argument("--download", action="store_true", help="also download flagged files (off by default)")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.jsonl"

    session = requests.Session()
    print(f"[*] Listing up to {args.limit} candidate repos (library={args.library or 'any'})...")
    candidates = list_candidates(args.limit, args.library, token=token)
    print(f"[*] Checking {len(candidates)} repos against HF's scan endpoint...")

    found = 0
    with open(manifest_path, "a") as manifest:
        for i, repo_id in enumerate(candidates):
            scan = scan_repo(repo_id, token=token, session=session)
            if i < args.debug_first:
                print(f"--- raw scan for {repo_id} ---")
                print(json.dumps(scan, indent=2)[:800] if scan else "(no response / non-200)")
            if not scan or not scan.get("hasUnsafeFile"):
                time.sleep(0.3)
                continue

            files = unsafe_files_from_scan(scan)
            entry = {"repo_id": repo_id, "files": files}
            manifest.write(json.dumps(entry) + "\n")
            manifest.flush()
            found += 1
            print(f"[UNSAFE] {repo_id} -> {files}")

            if args.download and files and "check raw JSON" not in files[0]:
                for fname in files:
                    try:
                        local = hf_hub_download(repo_id=repo_id, filename=fname, token=token,
                                                 local_dir=str(out_dir / repo_id.replace("/", "__")))
                        print(f"    downloaded -> {local}")
                    except Exception as e:
                        print(f"    [!] download failed for {repo_id}/{fname}: {e}")

            time.sleep(0.3)  # be polite to the API

    print(f"\n[+] Done. {found} flagged repos recorded in {manifest_path}")
    if not args.download:
        print("    Nothing downloaded yet. Check the manifest, confirm the filenames")
        print("    look right (see the debug JSON above), then re-run with --download.")


if __name__ == "__main__":
    main()
