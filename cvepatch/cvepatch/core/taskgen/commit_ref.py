"""Commit URL -> (clone URL, sha) for any git host, not just GitHub.

CVE references link fix commits on GitHub, GitLab, Bitbucket, googlesource,
cgit/gitweb, SourceForge and Gitea-style hosts; OSV GIT ranges give the repo
and the sha directly. Both end up as a CommitRef the task generator can clone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SHA = r"([0-9a-f]{7,40})"


@dataclass(frozen=True)
class CommitRef:
    repo: str                       # clone URL
    sha: str
    alt_repos: tuple[str, ...] = field(default=())   # tried if `repo` won't clone

    @property
    def slug(self) -> str:
        """host-less path, e.g. 'owner/name' on GitHub, 'group/sub/proj' on GitLab."""
        return repo_slug(self.repo)


def repo_slug(repo: str) -> str:
    u = urlsplit(repo)
    path = u.path.strip("/").removesuffix(".git")
    return path if u.netloc.lower() == "github.com" else f"{u.netloc.lower()}/{path}"


def _clean(repo: str) -> str:
    return repo.rstrip("/").removesuffix(".git")


# (pattern, repo builder). Order matters: specific hosts before the generic forms.
_RULES: list[tuple[re.Pattern, callable]] = [
    (re.compile(r"(https?://github\.com/[^/]+/[^/#?]+?)(?:\.git)?/(?:pull/\d+/)?commits?/" + SHA, re.I),
     lambda m: (_clean(m[1]), ())),
    (re.compile(r"(https?://[^/]+/.+?)/-/commits?/" + SHA, re.I),                   # GitLab (any host)
     lambda m: (_clean(m[1]), ())),
    (re.compile(r"(https?://bitbucket\.org/[^/]+/[^/#?]+)/commits?/" + SHA, re.I),
     lambda m: (_clean(m[1]), ())),
    (re.compile(r"(https?://[^/]+\.googlesource\.com/.+?)/\+/" + SHA, re.I),
     lambda m: (_clean(m[1]), ())),
    (re.compile(r"https?://sourceforge\.net/p/([^/]+)/([^/]+)/ci/" + SHA, re.I),
     lambda m: (f"https://git.code.sf.net/p/{m[1]}/{m[2]}", ())),
    # cgit: <repo>/commit/?id=<sha>   (also git.kernel.org)
    (re.compile(r"(https?://[^?#]+?)/(?:commit|patch|diff)/?\?(?:[^#]*&)?id=" + SHA, re.I),
     lambda m: (m[1].rstrip("/"), ())),
    # gitweb: ?p=<repo>;a=commit;h=<sha>  — the clone path varies by site
    (re.compile(r"(https?://[^/?#]+)(/[^?#]*)?\?(?:.*[;&])?p=([^;&#]+)[;&].*?\bh=" + SHA, re.I),
     lambda m: (f"{m[1]}/{m[3]}",
                (f"{m[1]}/git/{m[3]}", f"git://{urlsplit(m[1]).netloc}/{m[3]}"))),
    # Gitea / Gogs / Codeberg / Gitee and other <owner>/<repo>/commit/<sha> forges
    (re.compile(r"(https?://[^/]+/[^/]+/[^/#?]+?)(?:\.git)?/commits?/" + SHA, re.I),
     lambda m: (_clean(m[1]), ())),
]


# Hosts that moved; old CVE links still point at them.
_MOVED = [
    (re.compile(r"^https?://(?:cgit|anongit)\.freedesktop\.org/(?:git/)?(.+?)(?:\.git)?$"),
     r"https://gitlab.freedesktop.org/\1"),
    (re.compile(r"^https?://git\.gnome\.org/(?:browse/)?(.+?)(?:\.git)?$"),
     r"https://gitlab.gnome.org/GNOME/\1"),
]


def fallbacks(repo: str) -> tuple[str, ...]:
    out = [rx.sub(to, repo) for rx, to in _MOVED if rx.match(repo)]
    if repo.startswith("http://"):
        out.append("https://" + repo[len("http://"):])
    return tuple(out)


def parse_commit_url(url: str) -> CommitRef | None:
    for rx, build in _RULES:
        m = rx.search(url or "")
        if m:
            repo, alts = build(m)
            return CommitRef(repo, m.groups()[-1].lower(), (*fallbacks(repo), *alts))
    return None


def from_osv(repo: str, sha: str) -> CommitRef | None:
    """An OSV GIT range: `repo` is already a clone URL; `fixed` must be a sha."""
    if not repo or not re.fullmatch(r"[0-9a-f]{7,40}", (sha or "").lower()):
        return None
    return CommitRef(_clean(repo), sha.lower())
