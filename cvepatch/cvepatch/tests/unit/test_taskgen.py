"""Language-neutral task builder: adapters + core helpers.

Synthetic project trees only; no network and no repository code executed.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from cvepatch.core.taskgen import core
from cvepatch.core.taskgen.commit_ref import parse_commit_url, repo_slug
from cvepatch.core.taskgen.languages import (
    ADAPTERS,
    go_test_names,
    go_version_for,
    java_major,
)


def tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def test_all_languages_registered():
    assert set(ADAPTERS) == {"go", "python", "javascript", "java", "rust", "php", "ruby",
                             "native", "dotnet", "elixir"}
    for a in ADAPTERS.values():
        assert a.track.startswith("lang:") or a.track == "git-generic"


@pytest.mark.parametrize("url,repo,sha", [
    ("https://github.com/a/b.git/commit/ABCDEF1", "https://github.com/a/b", "abcdef1"),
    ("https://github.com/a/b/pull/7/commits/abcdef12", "https://github.com/a/b", "abcdef12"),
    ("https://gitlab.com/grp/sub/proj/-/commit/abcdef1", "https://gitlab.com/grp/sub/proj", "abcdef1"),
    ("https://gitlab.gnome.org/GNOME/glib/-/commit/abcdef1?x=1", "https://gitlab.gnome.org/GNOME/glib",
     "abcdef1"),
    ("https://bitbucket.org/o/r/commits/abcdef1", "https://bitbucket.org/o/r", "abcdef1"),
    ("https://chromium.googlesource.com/v8/v8/+/abcdef1234", "https://chromium.googlesource.com/v8/v8",
     "abcdef1234"),
    ("https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcdef123456",
     "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", "abcdef123456"),
    ("https://git.savannah.gnu.org/cgit/tar.git/commit/?h=master&id=abcdef123456",
     "https://git.savannah.gnu.org/cgit/tar.git", "abcdef123456"),
    ("https://sourceforge.net/p/net-snmp/code/ci/abcdef1/", "https://git.code.sf.net/p/net-snmp/code",
     "abcdef1"),
    ("https://codeberg.org/o/r/commit/abcdef1", "https://codeberg.org/o/r", "abcdef1"),
])
def test_parse_commit_url(url, repo, sha):
    ref = parse_commit_url(url)
    assert (ref.repo, ref.sha) == (repo, sha)


def test_parse_commit_url_gitweb_has_fallbacks():
    ref = parse_commit_url("https://git.example.org/?p=proj.git;a=commit;h=abcdef123456")
    assert (ref.repo, ref.sha) == ("https://git.example.org/proj.git", "abcdef123456")
    assert "git://git.example.org/proj.git" in ref.alt_repos


def test_parse_commit_url_moved_hosts():
    ref = parse_commit_url("http://cgit.freedesktop.org/poppler/poppler/commit/?id=abcdef123456")
    assert ref.repo == "http://cgit.freedesktop.org/poppler/poppler"
    assert ref.alt_repos[0] == "https://gitlab.freedesktop.org/poppler/poppler"
    ref = parse_commit_url("https://git.gnome.org/browse/glib/commit/?id=abcdef123456")
    assert ref.alt_repos[0] == "https://gitlab.gnome.org/GNOME/glib"


def test_parse_commit_url_rejects_non_commits():
    assert parse_commit_url("https://github.com/a/b/issues/3") is None
    assert parse_commit_url("not-a-url") is None


def test_repo_slug():
    assert repo_slug("https://github.com/acme/lib") == "acme/lib"
    assert repo_slug("https://gitlab.com/g/p.git") == "gitlab.com/g/p"


@pytest.mark.parametrize("lang,test,src,dep", [
    ("go", "pkg/x_test.go", "pkg/x.go", "go.sum"),
    ("python", "tests/test_auth.py", "app/auth.py", "requirements-dev.txt"),
    ("javascript", "src/auth.test.ts", "src/auth.ts", "package.json"),
    ("java", "core/src/test/java/a/AuthTest.java", "core/src/main/java/a/Auth.java", "pom.xml"),
    ("rust", "tests/auth.rs", "src/auth.rs", "Cargo.lock"),
    ("php", "tests/AuthTest.php", "src/Auth.php", "composer.json"),
    ("ruby", "spec/auth_spec.rb", "lib/auth.rb", "Gemfile.lock"),
])
def test_file_classification(lang, test, src, dep):
    a = ADAPTERS[lang]
    assert a.is_test(test) and not a.is_test(src)
    assert a.is_source(src)
    assert a.is_dep_file(dep) and not a.is_dep_file(src)


def test_ignored_paths():
    assert core.is_ignored("vendor/x/y.go") and core.is_ignored("a/node_modules/b.js")
    assert not core.is_ignored("internal/auth.go")


def test_go_helpers():
    diff = ("@@ -1,3 +1,6 @@ func TestOld(t *testing.T) {\n"
            "+func TestNew(t *testing.T) {}\n+func helper() {}\n")
    assert go_test_names(diff) == ["TestNew", "TestOld"]
    assert go_version_for("go 1.18\n") == "1.20" and go_version_for("go 1.23.1") == "1.23"


def test_java_major():
    assert java_major("<maven.compiler.source>1.8</maven.compiler.source>") == 8
    assert java_major("<java.version>17</java.version>") == 17
    assert java_major("JavaLanguageVersion.of(21)") == 21
    assert java_major("nothing") == 17


def test_go_plan(tmp_path):
    b = tree(tmp_path, {"go.mod": "module m\n\ngo 1.21\n", "auth/a.go": "", "auth/a_test.go": ""})
    plan = ADAPTERS["go"].plan(b, ["auth/a_test.go"], ["auth/a.go"],
                               "+func TestBypass(t *testing.T) {", [])
    assert plan.image == "golang:1.21-bookworm"
    assert "'^(TestBypass)$'" in plan.oracle and "./auth" in plan.oracle
    assert plan.existing[:4] == ["go", "test", "-count=1", "-skip"]


def test_python_plan_points_imports_at_tree_under_test(tmp_path):
    b = tree(tmp_path, {"pyproject.toml": 'requires-python = ">=3.8"\n', "app/auth.py": "",
                        "tests/test_auth.py": "", "tests/test_other.py": ""})
    plan = ADAPTERS["python"].plan(b, ["tests/test_auth.py"], ["app/auth.py"],
                                   "+def test_no_bypass():\n", ["tests/test_other.py"])
    assert plan.image == "python:3.9-bookworm"
    assert 'PYTHONPATH="$PWD/src:$PWD' in plan.oracle
    assert "-k test_no_bypass" in plan.oracle
    assert "tests/test_other.py" in plan.existing[-1]


def test_python_needs_project_file(tmp_path):
    with pytest.raises(core.SkipCandidate):
        ADAPTERS["python"].plan(tmp_path, ["tests/test_a.py"], ["a.py"], "", [])


def test_js_plan_detects_runner_and_lockfile(tmp_path):
    b = tree(tmp_path, {"package.json": json.dumps({"devDependencies": {"jest": "29"},
                                                    "engines": {"node": ">=16"}}),
                        "package-lock.json": "{}"})
    plan = ADAPTERS["javascript"].plan(b, ["src/a.test.js"], ["src/a.js"], "", [])
    assert plan.image == "node:18-bookworm"
    assert plan.oracle.startswith("npx jest --ci")
    assert any("npm ci" in w for w in plan.warm)


def test_js_unknown_runner_skips(tmp_path):
    b = tree(tmp_path, {"package.json": "{}"})
    with pytest.raises(core.SkipCandidate):
        ADAPTERS["javascript"].plan(b, ["a.test.js"], ["a.js"], "", [])


def test_java_maven_multimodule(tmp_path):
    b = tree(tmp_path, {"pom.xml": "<java.version>11</java.version>", "core/pom.xml": "",
                        "core/src/test/java/a/AuthTest.java": "",
                        "core/src/main/java/a/Auth.java": ""})
    plan = ADAPTERS["java"].plan(b, ["core/src/test/java/a/AuthTest.java"],
                                 ["core/src/main/java/a/Auth.java"], "", [])
    assert plan.image == "maven:3.9-eclipse-temurin-11"
    assert "-pl core -am" in plan.oracle and "-Dtest=AuthTest" in plan.oracle
    assert "-o" in plan.oracle.split()          # offline at grading time


def test_rust_integration_tests_only(tmp_path):
    b = tree(tmp_path, {"Cargo.toml": '[package]\nname = "auth"\n'})
    plan = ADAPTERS["rust"].plan(b, ["tests/bypass.rs"], ["src/lib.rs"], "", [])
    assert plan.oracle == "cargo test --offline -p auth --test bypass"


def test_php_requires_phpunit(tmp_path):
    b = tree(tmp_path, {"composer.json": json.dumps({"require": {"php": ">=8.1"},
                                                     "require-dev": {"phpunit/phpunit": "^10"}})})
    plan = ADAPTERS["php"].plan(b, ["tests/AuthTest.php"], ["src/Auth.php"], "", [])
    assert plan.image == "php:8.1-cli"
    tree(tmp_path / "x", {"composer.json": "{}"})
    with pytest.raises(core.SkipCandidate):
        ADAPTERS["php"].plan(tmp_path / "x", ["tests/AuthTest.php"], ["src/A.php"], "", [])


def test_ruby_rspec(tmp_path):
    b = tree(tmp_path, {"Gemfile": "", ".ruby-version": "3.1.4\n"})
    plan = ADAPTERS["ruby"].plan(b, ["spec/auth_spec.rb"], ["lib/auth.rb"], "", [])
    assert plan.image == "ruby:3.1-bookworm"
    assert plan.oracle == "bundle exec rspec spec/auth_spec.rb"


def test_oracle_script_quotes_compile_pattern():
    sh = core.ORACLE_SH.format(oracle="true", compile_re=shlex.quote(r"a|b \[x\]"))
    assert "grep -qE 'a|b \\[x\\]'" in sh


def test_complete_bundle_is_reused_not_rewritten(tmp_path):
    out = tmp_path / "go-cve-2099-0001"
    for f in core.BUNDLE_FILES:
        (out / f).parent.mkdir(parents=True, exist_ok=True)
        (out / f).write_text("{}" if f == "meta.json" else "x")
    (out / "baseline").mkdir()
    (out / "baseline" / "go.mod").write_text("module m\n")
    # The commit URL is never touched: a reused bundle needs no clone.
    meta = core.build_task("CVE-2099-0001", "not-a-url", tmp_path / "cache", tmp_path,
                           ADAPTERS["go"])
    assert meta["reused"] and (out / "Dockerfile").read_text() == "x"
    (out / "meta.json").unlink()
    assert not core.bundle_complete(out)


def _repo_with_fix(cache: Path) -> str:
    """A tiny local 'GitHub' repo (in the clone cache) with a vuln and a fix commit."""
    import subprocess

    repo = cache / "acme__lib"
    tree(repo, {"pyproject.toml": '[project]\nname = "lib"\nrequires-python = ">=3.10"\n',
                "lib/__init__.py": "",
                "lib/auth.py": "def allowed(user):\n    return True\n",
                "tests/test_auth.py": "from lib.auth import allowed\n\n\ndef test_ok():\n"
                                      "    assert allowed('admin')\n",
                "tests/test_other.py": "def test_other():\n    assert True\n"})

    def g(*a):
        return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True,
                              text=True).stdout.strip()
    g("init", "-q")
    g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "vuln")
    (repo / "lib" / "auth.py").write_text("def allowed(user):\n    return user == 'admin'\n")
    with (repo / "tests" / "test_auth.py").open("a") as fh:
        fh.write("\n\ndef test_guest_denied():\n    assert not allowed('guest')\n")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "fix auth bypass")
    return g("rev-parse", "HEAD")


def test_bundle_keeps_answer_out_of_the_image(tmp_path):
    from cvepatch.core.manifest import from_dict as task_from_dict

    cache = tmp_path / "cache"
    sha = _repo_with_fix(cache)
    adv = {"cve_id": "CVE-2099-0002", "description": "auth bypass in allowed()",
           "cwe_ids": ["CWE-863"]}
    meta = core.build_task("CVE-2099-0002", f"https://github.com/acme/lib/commit/{sha}",
                           cache, tmp_path / "out", ADAPTERS["python"], advisory=adv)
    out = tmp_path / "out" / meta["task_id"]
    assert core.bundle_complete(out)
    assert (out / "hidden/oracle/files/tests/test_auth.py").read_text().count("def test_") == 2
    assert "user == 'admin'" in (out / "hidden/reference/fix.patch").read_text()
    assert "test_guest_denied" in (out / "hidden/reference/test.patch").read_text()
    # baseline is the vulnerable tree; the image only gets baseline/ + public/
    assert "return True" in (out / "baseline/lib/auth.py").read_text()
    docker = (out / "Dockerfile").read_text()
    assert "hidden" not in docker and "COPY public/" in docker
    assert "hidden/" in (out / ".dockerignore").read_text()
    # public task: schema-valid, has the advisory, nothing that points at the fix
    pub_text = (out / "public/defensive_task.json").read_text()
    pub = task_from_dict(json.loads(pub_text))
    assert pub.raw["metadata"]["advisory"]["description"] == "auth bypass in allowed()"
    for leak in (sha, sha[:7], "test_guest_denied", "test_auth.py", "test_other.py", "oracle"):
        assert leak not in pub_text, leak
    full = json.loads((out / "hidden/task.json").read_text())
    assert full["fixed_commit"] == sha
    assert full["metadata"]["oracle_command"] and full["metadata"]["compile_fail_re"]
    env = (out / "env_manifest.yaml").read_text()
    assert "cvepatch.core.verifier.verify" in env and "target: /opt/hidden" in env


def test_advisory_scrubs_fix_commit():
    from cvepatch.core.ingestion.advisory import scrub, scrub_advisory
    sha = "3f8383aa89f45d861ca081e3e9fd2cc9d0b5dfaa"
    out = scrub(f"Upgrade to 1.6.0. Patch name: {sha}. See https://github.com/a/b/commit/{sha[:9]}")
    assert sha not in out and sha[:9] not in out and "1.6.0" in out
    # deep scrub reaches affected-version strings, not just the description
    adv = {"description": f"bug fixed in {sha}", "cwe_ids": ["CWE-20"],
           "affected": [{"versions": [{"version": f"< commit {sha}"}]}]}
    cleaned = scrub_advisory(adv)
    assert sha not in json.dumps(cleaned) and cleaned["cwe_ids"] == ["CWE-20"]


def _repo_code_only_fix(cache: Path) -> str:
    """A tiny repo whose fix commit changes only source (ships no test)."""
    import subprocess
    repo = cache / "acme__nolib"
    tree(repo, {"pyproject.toml": '[project]\nname = "nolib"\nrequires-python = ">=3.10"\n',
                "nolib/__init__.py": "",
                "nolib/auth.py": "def allowed(user):\n    return True\n",
                "tests/test_smoke.py": "def test_import():\n    import nolib  # noqa\n"})

    def g(*a):
        return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True,
                              text=True).stdout.strip()
    g("init", "-q")
    g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "vuln")
    (repo / "nolib" / "auth.py").write_text("def allowed(user):\n    return user == 'admin'\n")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "fix: no test shipped")
    return g("rev-parse", "HEAD")


def test_fix_without_tests_makes_a_no_oracle_bundle(tmp_path):
    cache = tmp_path / "cache"
    sha = _repo_code_only_fix(cache)
    meta = core.build_task("CVE-2099-0003", f"https://github.com/acme/nolib/commit/{sha}",
                           cache, tmp_path / "out", ADAPTERS["python"],
                           advisory={"cve_id": "CVE-2099-0003", "description": "auth bypass",
                                     "cwe_ids": ["CWE-863"]})
    out = tmp_path / "out" / meta["task_id"]
    assert core.bundle_complete(out)
    assert meta["has_oracle"] is False
    assert not (out / "hidden" / "oracle").exists()          # no upstream oracle
    assert "user == 'admin'" in (out / "hidden/reference/fix.patch").read_text()
    full = json.loads((out / "hidden/task.json").read_text())
    assert full["metadata"]["has_oracle"] is False
    assert full["build_instructions"]["toolchain"]["image"].startswith("python:3.")
    assert full["build_instructions"]["command"][0] == "python"      # env_plan build (compileall)
    assert full["regression_test_command"]["command"] == ["true"]    # agent writes the test
    # answer still hidden from the public task
    assert sha not in (out / "public/defensive_task.json").read_text()


def test_run_git_retries_only_transient_errors(monkeypatch):
    import subprocess as sp
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        err = "fatal: unable to access 'https://github.com/a/b/': Could not resolve host: github.com"
        ok = len(calls) >= 3
        return sp.CompletedProcess(cmd, 0 if ok else 128, "", "" if ok else err)
    monkeypatch.setattr(core.subprocess, "run", fake_run)
    monkeypatch.setattr(core.time, "sleep", lambda s: None)
    assert core.run_git(["git", "clone"], capture_output=True, text=True).returncode == 0
    assert len(calls) == 3
    calls.clear()
    monkeypatch.setattr(core.subprocess, "run", lambda cmd, **kw: (calls.append(cmd), sp.CompletedProcess(
        cmd, 128, "", "fatal: repository not found"))[1])
    assert core.run_git(["git", "clone"]).returncode == 128 and len(calls) == 1


def _git_repo(path: Path, files: dict[str, str]):
    import subprocess

    def g(*a):
        return subprocess.run(["git", "-C", str(path), *a], check=True, capture_output=True,
                              text=True).stdout.strip()
    tree(path, files)
    g("init", "-q")
    g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "vuln")

    def commit(changes: dict[str, str], msg: str) -> str:
        tree(path, changes)
        g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
        g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", msg)
        return g("rev-parse", "HEAD")
    return commit


PY_FILES = {"pyproject.toml": '[project]\nname = "lib"\n', "lib/__init__.py": "",
            "lib/auth.py": "def allowed(u):\n    return True\n"}


def test_keep_all_keeps_dependency_changes_with_a_label(tmp_path):
    commit = _git_repo(tmp_path / "cache" / "acme__lib", PY_FILES)
    sha = commit({"pyproject.toml": '[project]\nname = "lib"\ndependencies = ["x>=2"]\n',
                  "lib/auth.py": "def allowed(u):\n    return u == 'admin'\n"}, "fix")
    url = f"https://github.com/acme/lib/commit/{sha}"
    with pytest.raises(core.SkipCandidate, match="dependency"):
        core.build_task("CVE-2099-0101", url, tmp_path / "cache", tmp_path / "out", ADAPTERS["python"])
    meta = core.build_task("CVE-2099-0101", url, tmp_path / "cache", tmp_path / "out",
                           ADAPTERS["python"], keep_all=True)
    assert meta["labels"]["deps_changed"] is True
    task = json.loads((tmp_path / "out" / meta["task_id"] / "hidden" / "task.json").read_text())
    assert task["metadata"]["labels"]["deps_changed"] is True


def test_keep_all_falls_back_to_agent_setup_when_the_builder_cannot(tmp_path):
    commit = _git_repo(tmp_path / "cache" / "acme__gosvc",
                       {"svc/main.go": "package main\nfunc f(n int) int { return n }\n"})
    sha = commit({"svc/main.go": "package main\nfunc f(n int) int { if n < 0 { return 0 }; return n }\n"},
                 "fix")
    meta = core.build_task("CVE-2099-0102", f"https://github.com/acme/gosvc/commit/{sha}",
                           tmp_path / "cache", tmp_path / "out", ADAPTERS["go"], keep_all=True)
    assert meta["labels"]["env"] == "agent_setup" and "go.mod" in meta["labels"]["builder_skip"]
    assert meta["setup_mode"] == "agent" and meta["task_id"] == "go-cve-2099-0102"
    assert "FROM golang:" in (tmp_path / "out" / meta["task_id"] / "Dockerfile").read_text()


def test_build_first_prefers_a_ref_with_code(tmp_path):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
    import taskgen
    commit = _git_repo(tmp_path / "cache" / "acme__lib", PY_FILES)
    real = commit({"lib/auth.py": "def allowed(u):\n    return u == 'admin'\n"}, "fix")
    bump = commit({"VERSION": "1.0.1\n"}, "release")
    row = {"cve": "CVE-2099-0103", "fix_refs": [{"repo": "https://github.com/acme/lib", "sha": bump},
                                                {"repo": "https://github.com/acme/lib", "sha": real}]}
    meta, used = taskgen.build_first(row, taskgen.commit_refs(row), cache=tmp_path / "cache",
                                     out_root=tmp_path / "out", adapter=ADAPTERS["python"],
                                     keep_all=True)
    assert used.sha == real and "ref" not in meta["labels"]
    row2 = {"cve": "CVE-2099-0104", "fix_refs": [{"repo": "https://github.com/acme/lib", "sha": bump}]}
    meta2, _ = taskgen.build_first(row2, taskgen.commit_refs(row2), cache=tmp_path / "cache",
                                   out_root=tmp_path / "out", adapter=ADAPTERS["python"],
                                   keep_all=True)
    assert meta2["labels"]["ref"] == "no_code_fix"
