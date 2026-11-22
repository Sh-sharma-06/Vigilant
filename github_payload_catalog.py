"""
github_payload_catalog.py — finds candidate pickle-payload-generation
scripts on public GitHub, for the Vigilant eval dataset.

This only searches GitHub's code search API and records links + which repo/
path they're in, for a human to review. It does not download full file
contents or run anything automatically. Once you've looked at a hit and
decided it's worth keeping, use fetch_one() below to pull just that file's
raw text.

Needs a GitHub personal access token — code search requires auth even for
public repos:
    export GITHUB_TOKEN=ghp_xxx
    python3 github_payload_catalog.py --out github_candidates.jsonl
"""

import argparse
import json
import os
import time

import requests

SEARCH_URL = "https://api.github.com/search/code"

QUERIES = [
    '"__reduce__ =" pickle.dumps',
    '"__builtin__" pickle.dumps eval',
    'posix system pickle.dumps extension:py',
]


def search(query, token, page=1):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    params = {"q": query, "per_page": 30, "page": page}
    resp = requests.get(SEARCH_URL, headers=headers, params=params, timeout=30)
    if resp.status_code == 403:
        wait = int(resp.headers.get("Retry-After", "60"))
        print(f"    rate-limited, waiting {wait}s...")
        time.sleep(wait)
        return search(query, token, page)
    resp.raise_for_status()
    return resp.json()


def fetch_one(repo, path, ref="main", token=None):
    """Pull one specific file's raw text after reviewing it at its html_url.
    Returns text only — nothing here executes it."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="github_candidates.jsonl")
    ap.add_argument("--max-per-query", type=int, default=30)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Set GITHUB_TOKEN first — GitHub's code search requires auth even for public repos.")
        return

    seen = set()
    with open(args.out, "w") as out:
        for q in QUERIES:
            print(f"[*] {q}")
            try:
                data = search(q, token)
            except requests.HTTPError as e:
                print(f"    failed: {e}")
                continue
            for item in data.get("items", [])[: args.max_per_query]:
                key = item["html_url"]
                if key in seen:
                    continue
                seen.add(key)
                row = {
                    "query": q,
                    "repo": item["repository"]["full_name"],
                    "path": item["path"],
                    "url": item["html_url"],
                }
                out.write(json.dumps(row) + "\n")
                print("   ", row["repo"], row["path"])
            time.sleep(2)

    print(f"\n[+] {len(seen)} candidate links saved to {args.out}")
    print("    Nothing downloaded. Open the URLs, read them yourself, then use")
    print("    fetch_one(repo, path) for anything you've reviewed and want to keep.")


if __name__ == "__main__":
    main()
