# SPDX-License-Identifier: Apache-2.0
"""MkDocs hook: links from the docs to files outside docs/ (ROADMAP.md, adr/, charts/, config/, ...) point to
those files on GitHub, since the site publishes only docs/. The Markdown sources keep their relative links, which
work when reading the repository on GitHub and are checked by tools/docs/check_links.py."""

from __future__ import annotations

import posixpath
import re
from pathlib import Path
from typing import Any

FENCE = re.compile(r"^(\s*)(```|~~~)")
LINK = re.compile(r"(\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))")


def _github(target: str, page_dir: str, docs: Path, repo: Path, repo_url: str) -> str | None:
    if re.match(r"^[a-z][a-z0-9+.-]*:|^/|^#", target):
        return None  # a URL, a site-absolute path or an anchor on the page
    path, _, anchor = target.partition("#")
    resolved = posixpath.normpath(posixpath.join(page_dir, path))
    if not resolved.startswith("../"):
        return None  # inside docs/: MkDocs resolves it
    in_repo = posixpath.normpath(posixpath.join("docs", resolved))
    if in_repo.startswith("../") or in_repo == "..":
        return None  # outside the repository
    full = repo / in_repo
    kind = "tree" if in_repo == "." or full.is_dir() else "blob"
    url = f"{repo_url.rstrip('/')}/{kind}/main" + ("" if in_repo == "." else f"/{in_repo}")
    return url + (f"#{anchor}" if anchor else "")


def on_page_markdown(markdown: str, page: Any, config: Any, files: Any) -> str:
    docs = Path(config["docs_dir"]).resolve()
    repo = docs.parent
    repo_url = config.get("repo_url") or ""
    page_dir = posixpath.dirname(page.file.src_uri)
    out, fence = [], None
    for line in markdown.split("\n"):
        m = FENCE.match(line)
        if m:
            fence = None if fence == m.group(2) else (fence or m.group(2))
            out.append(line)
            continue
        if fence or not repo_url:
            out.append(line)
            continue

        def swap(m: re.Match[str]) -> str:
            url = _github(m.group(2), page_dir, docs, repo, repo_url)
            return f"{m.group(1)}{url}{m.group(3)}" if url else m.group(0)

        out.append(LINK.sub(swap, line))
    return "\n".join(out)
