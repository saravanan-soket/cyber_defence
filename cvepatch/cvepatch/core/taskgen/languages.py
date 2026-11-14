"""Per-language adapters for the shared task builder (core.py).

Each adapter only decides: which files are tests / source / dependency
manifests, how to run just the fix's tests, how to warm dependencies at image
build time, and which base image to use. Repository code is never run here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from cvepatch.core.taskgen.core import Adapter, Plan, SkipCandidate, q
from cvepatch.core.taskgen.setup_adapters import SETUP_ADAPTERS

# ======================================================================= Go

GO_TEST_FUNC_RE = re.compile(r"^\+?func (Test\w+)\s*\(", re.M)
GO_HUNK_FUNC_RE = re.compile(r"^@@[^@]*@@\s*func (Test\w+)\s*\(", re.M)
GO_DIRECTIVE_RE = re.compile(r"^go\s+(\d+)\.(\d+)", re.M)


def added_lines(diff: str) -> str:
    return "\n".join(ln for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))


def go_test_names(diff: str) -> list[str]:
    names = set(GO_TEST_FUNC_RE.findall(added_lines(diff))) | set(GO_HUNK_FUNC_RE.findall(diff))
    return sorted(names)


def go_version_for(go_mod: str) -> str:
    m = GO_DIRECTIVE_RE.search(go_mod)
    if not m:
        raise SkipCandidate("go.mod has no go directive")
    if int(m.group(1)) != 1:
        raise SkipCandidate("unexpected go major version")
    return f"1.{max(int(m.group(2)), 20)}"   # `go test -skip` needs 1.20+


def pkg_dir(p: str) -> str:
    d = str(Path(p).parent)
    return "." if d == "." else "./" + d


class GoAdapter(Adapter):
    name, track = "go", "lang:go"
    dep_files = ("go.mod", "go.sum", "go.work", "go.work.sum")

    def is_test(self, p): return p.endswith("_test.go")
    def is_source(self, p): return p.endswith(".go")

    def plan(self, baseline, tests, code, test_diff, siblings):
        gomod = baseline / "go.mod"
        if not gomod.exists():
            raise SkipCandidate("no go.mod at repo root (GOPATH-era or nested module)")
        ver = go_version_for(gomod.read_text(errors="replace"))
        names = go_test_names(test_diff)
        if not names:
            raise SkipCandidate("could not identify changed test functions")
        run_re = "^(" + "|".join(names) + ")$"
        tpkgs = sorted({pkg_dir(t) for t in tests})
        pkgs = sorted({pkg_dir(p) for p in tests + code})
        return Plan(
            image=f"golang:{ver}-bookworm",
            oracle=f"go test -count=1 -run {q([run_re])} {q(tpkgs)}",
            compile_fail_re=r"\[(build|setup) failed\]|^# ",
            build=["go", "build", *pkgs],
            existing=["go", "test", "-count=1", "-skip", run_re, *pkgs],
            agent_tests={},
            # Whole-module warm: nothing in the image may point at the fixed package.
            warm=["go mod download", "(go build ./... || true)",
                  "(go test -count=1 -run '^$' ./... >/dev/null 2>&1 || true)"],
            build_env={"GOTOOLCHAIN": "local", "GOFLAGS": "-buildvcs=false",
                       "GOCACHE": "/opt/cache/go", "GOPATH": "/go"},
            runtime_env={"GOPROXY": "off"},
            chown=["/go"],
            notes={"go": ver, "oracle_tests": names},
        )


    def env_plan(self, baseline, code):
        gomod = baseline / "go.mod"
        if not gomod.exists():
            raise SkipCandidate("no go.mod at repo root (GOPATH-era or nested module)")
        ver = go_version_for(gomod.read_text(errors="replace"))
        pkgs = sorted({pkg_dir(p) for p in code}) or ["./..."]
        return Plan(
            image=f"golang:{ver}-bookworm", oracle="",
            compile_fail_re=r"\[(build|setup) failed\]|^# ",
            build=["go", "build", *pkgs], existing=None, agent_tests={},
            warm=["go mod download", "(go build ./... || true)"],
            build_env={"GOTOOLCHAIN": "local", "GOFLAGS": "-buildvcs=false",
                       "GOCACHE": "/opt/cache/go", "GOPATH": "/go"},
            runtime_env={"GOPROXY": "off"}, chown=["/go"],
            notes={"go": ver, "no_upstream_oracle": True},
        )


# =================================================================== Python

PY_DEF_RE = re.compile(r"^\+\s*(?:async\s+)?def (test\w*)\s*\(|^\+\s*class (Test\w*)", re.M)
PY_HUNK_RE = re.compile(r"^@@[^@]*@@\s*(?:async\s+)?(?:def (test\w*)|class (Test\w*))", re.M)
PY_REQ_RE = re.compile(r"(?:requires-python|python_requires)\s*=\s*['\"][^0-9]*3\.(\d+)")


class PythonAdapter(Adapter):
    name, track = "python", "lang:python"
    dep_files = ("setup.py", "setup.cfg", "pyproject.toml", "poetry.lock", "Pipfile",
                 "Pipfile.lock", "uv.lock", "pdm.lock")
    dep_prefixes = ("requirements",)

    def is_test(self, p):
        if not p.endswith(".py"):
            return False
        b = Path(p).name
        return (b.startswith("test_") or b.endswith("_test.py") or b == "conftest.py"
                or p.startswith(("tests/", "test/")) or "/tests/" in p or "/test/" in p)

    def is_source(self, p): return p.endswith(".py")

    def plan(self, baseline, tests, code, test_diff, siblings):
        cfg = [baseline / f for f in ("pyproject.toml", "setup.py", "setup.cfg")]
        if not any(f.exists() for f in cfg):
            raise SkipCandidate("no pyproject.toml/setup.py (not an installable Python project)")
        text = " ".join(f.read_text(errors="replace") for f in cfg if f.exists())
        m = PY_REQ_RE.search(text)
        minor = min(max(int(m.group(1)), 9), 12) if m else 11
        names = sorted({a or b for a, b in PY_DEF_RE.findall(test_diff)}
                       | {a or b for a, b in PY_HUNK_RE.findall(test_diff)})
        pyfiles = [t for t in tests if Path(t).name != "conftest.py"] or tests
        k = f" -k {q([' or '.join(names)])}" if names else ""
        pp = 'PYTHONPATH="$PWD/src:$PWD${PYTHONPATH:+:$PYTHONPATH}"'
        pytest = "python -m pytest -q -p no:cacheprovider -o addopts=''"
        existing = (["bash", "-c", f"{pp} {pytest} {q(siblings)}"] if siblings else None)
        install = ("(pip install --no-cache-dir '.[test]' || pip install --no-cache-dir '.[tests]'"
                   " || pip install --no-cache-dir '.[dev]' || pip install --no-cache-dir .)")
        reqs = ("for f in requirements-test*.txt requirements-dev*.txt test-requirements.txt "
                "dev-requirements.txt requirements/test*.txt requirements/dev*.txt; do "
                "[ -f \"$f\" ] && pip install --no-cache-dir -r \"$f\" || true; done")
        return Plan(
            image=f"python:3.{minor}-bookworm",
            # PYTHONPATH points imports at the tree under test, not the copy
            # installed into site-packages while warming dependencies.
            oracle=f"{pp} {pytest} {q(pyfiles)}{k}",
            compile_fail_re=r"ERROR collecting|ImportError while importing|ModuleNotFoundError|"
                            r"SyntaxError|no tests ran|collected 0 items|cannot import name",
            build=["python", "-m", "compileall", "-q", *sorted({str(Path(c).parent) for c in code})],
            existing=existing,
            agent_tests={},
            warm=[install, reqs, "pip install --no-cache-dir pytest"],
            build_env={"PIP_DISABLE_PIP_VERSION_CHECK": "1"},
            runtime_env={"PIP_NO_INDEX": "1"},
            notes={"python": f"3.{minor}", "oracle_tests": names},
        )


    def env_plan(self, baseline, code):
        cfg = [baseline / f for f in ("pyproject.toml", "setup.py", "setup.cfg")]
        if not any(f.exists() for f in cfg):
            raise SkipCandidate("no pyproject.toml/setup.py (not an installable Python project)")
        text = " ".join(f.read_text(errors="replace") for f in cfg if f.exists())
        m = PY_REQ_RE.search(text)
        minor = min(max(int(m.group(1)), 9), 12) if m else 11
        install = ("(pip install --no-cache-dir '.[test]' || pip install --no-cache-dir '.[tests]'"
                   " || pip install --no-cache-dir '.[dev]' || pip install --no-cache-dir .)")
        reqs = ("for f in requirements-test*.txt requirements-dev*.txt test-requirements.txt "
                "dev-requirements.txt requirements/test*.txt requirements/dev*.txt; do "
                "[ -f \"$f\" ] && pip install --no-cache-dir -r \"$f\" || true; done")
        return Plan(
            image=f"python:3.{minor}-bookworm", oracle="",
            compile_fail_re=r"ERROR collecting|ImportError while importing|ModuleNotFoundError|"
                            r"SyntaxError|no tests ran|collected 0 items|cannot import name",
            build=["python", "-m", "compileall", "-q", *sorted({str(Path(c).parent) for c in code})],
            existing=None, agent_tests={},
            warm=[install, reqs, "pip install --no-cache-dir pytest"],
            build_env={"PIP_DISABLE_PIP_VERSION_CHECK": "1"}, runtime_env={"PIP_NO_INDEX": "1"},
            notes={"python": f"3.{minor}", "no_upstream_oracle": True},
        )


# ============================================================== JavaScript

JS_TEST_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(/__tests__/)|(^|/)(test|tests)/.+\.[cm]?[jt]sx?$")
JS_SRC_RE = re.compile(r"\.([cm]?[jt]sx?)$")
JS_RUNNERS = ("vitest", "jest", "mocha", "ava", "tap")


class JavaScriptAdapter(Adapter):
    name, track = "javascript", "lang:javascript"
    dep_files = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                 "npm-shrinkwrap.json", "bun.lockb")

    def is_test(self, p): return bool(JS_TEST_RE.search(p))
    def is_source(self, p): return bool(JS_SRC_RE.search(p)) and not p.endswith(".d.ts")

    def plan(self, baseline, tests, code, test_diff, siblings):
        pj = baseline / "package.json"
        if not pj.exists():
            raise SkipCandidate("no package.json at repo root")
        pkg = json.loads(pj.read_text(errors="replace") or "{}")
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        script = (pkg.get("scripts") or {}).get("test", "")
        runner = next((r for r in JS_RUNNERS if r in deps or r in script), None)
        if runner is None and "node --test" in script:
            runner = "node"
        if runner is None:
            raise SkipCandidate("unknown JS test runner")
        m = re.search(r"(\d+)", str((pkg.get("engines") or {}).get("node", "")))
        node = min(max(int(m.group(1)), 18), 22) if m else 20
        if (baseline / "pnpm-lock.yaml").exists():
            install = ("corepack enable && (pnpm install --frozen-lockfile"
                       " || pnpm install --no-frozen-lockfile)")
        elif (baseline / "yarn.lock").exists():
            install = ("corepack enable && (yarn install --frozen-lockfile"
                       " || yarn install --immutable || yarn install)")
        elif (baseline / "package-lock.json").exists():
            install = "npm ci --no-audit --no-fund"
        else:
            install = "npm install --no-audit --no-fund"

        def run(files):
            return {"vitest": f"npx vitest run {q(files)}", "jest": f"npx jest --ci {q(files)}",
                    "mocha": f"npx mocha {q(files)}", "ava": f"npx ava {q(files)}",
                    "tap": f"npx tap {q(files)}", "node": f"node --test {q(files)}"}[runner]
        existing = ["bash", "-c", run(siblings)] if siblings else None
        return Plan(
            image=f"node:{node}-bookworm",
            oracle=run(tests),
            compile_fail_re=r"Cannot find module|SyntaxError|Test suite failed to run|"
                            r"ERR_MODULE_NOT_FOUND|TS[0-9]{4}:|is not exported|does not provide an export",
            build=["npm", "run", "build", "--if-present"],
            existing=existing,
            agent_tests={},
            warm=[install, "(npm run build --if-present || true)"],
            build_env={"npm_config_cache": "/opt/cache/npm", "CI": "true"},
            runtime_env={"npm_config_offline": "true"},
            notes={"node": node, "runner": runner},
        )


    def env_plan(self, baseline, code):
        pj = baseline / "package.json"
        if not pj.exists():
            raise SkipCandidate("no package.json at repo root")
        pkg = json.loads(pj.read_text(errors="replace") or "{}")
        m = re.search(r"(\d+)", str((pkg.get("engines") or {}).get("node", "")))
        node = min(max(int(m.group(1)), 18), 22) if m else 20
        if (baseline / "pnpm-lock.yaml").exists():
            install = ("corepack enable && (pnpm install --frozen-lockfile"
                       " || pnpm install --no-frozen-lockfile)")
        elif (baseline / "yarn.lock").exists():
            install = ("corepack enable && (yarn install --frozen-lockfile"
                       " || yarn install --immutable || yarn install)")
        elif (baseline / "package-lock.json").exists():
            install = "npm ci --no-audit --no-fund"
        else:
            install = "npm install --no-audit --no-fund"
        return Plan(
            image=f"node:{node}-bookworm", oracle="",
            compile_fail_re=r"Cannot find module|SyntaxError|Test suite failed to run|"
                            r"ERR_MODULE_NOT_FOUND|TS[0-9]{4}:|is not exported|does not provide an export",
            build=["npm", "run", "build", "--if-present"], existing=None, agent_tests={},
            warm=[install, "(npm run build --if-present || true)"],
            build_env={"npm_config_cache": "/opt/cache/npm", "CI": "true"},
            runtime_env={"npm_config_offline": "true"},
            notes={"node": node, "no_upstream_oracle": True},
        )


# ==================================================================== Java

JAVA_VER_RES = [re.compile(p) for p in (
    r"<maven\.compiler\.release>\s*(\d+(?:\.\d+)?)", r"<maven\.compiler\.source>\s*(\d+(?:\.\d+)?)",
    r"<java\.version>\s*(\d+(?:\.\d+)?)", r"<release>\s*(\d+)\s*</release>",
    r"JavaLanguageVersion\.of\(\s*(\d+)", r"sourceCompatibility\s*=\s*['\"]?(?:JavaVersion\.VERSION_)?(\d+(?:[._]\d+)?)")]
MVN_SKIPS = ("-Dcheckstyle.skip -Denforcer.skip -Dspotbugs.skip -Dpmd.skip -Drat.skip "
             "-Djacoco.skip -Dmaven.javadoc.skip -Dlicense.skip -Dspotless.check.skip "
             "-Danimal.sniffer.skip -Dgpg.skip")


def java_major(text: str) -> int:
    for rx in JAVA_VER_RES:
        m = rx.search(text)
        if m:
            v = m.group(1).replace("_", ".")
            n = int(v.split(".")[1]) if v.startswith("1.") else int(float(v))
            return next(t for t in (8, 11, 17, 21) if t >= n) if n <= 21 else 21
    return 17


# Offline builds also need the build's own plugins (buildscript classpath) and
# every configuration's dependencies, which testClasses alone may not fetch.
GRADLE_RESOLVE = ("(./gradlew --no-daemon -q buildEnvironment >/dev/null; "
                  "./gradlew --no-daemon -q dependencies >/dev/null; true)")


class JavaAdapter(Adapter):
    name, track = "java", "lang:java"
    dep_files = ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
                 "settings.gradle.kts", "gradle.properties", "libs.versions.toml",
                 "gradle-wrapper.properties")

    def is_test(self, p): return "src/test/" in p and p.endswith((".java", ".kt"))
    def is_source(self, p): return "src/main/" in p and p.endswith((".java", ".kt"))

    @staticmethod
    def module_of(baseline: Path, path: str, marker: tuple[str, ...]) -> str:
        d = Path(path).parent
        while True:
            if any((baseline / d / m).exists() for m in marker):
                return str(d)
            if d == Path("."):
                return "."
            d = d.parent

    def plan(self, baseline, tests, code, test_diff, siblings):
        maven = (baseline / "pom.xml").exists()
        gradle = any((baseline / f).exists() for f in ("build.gradle", "build.gradle.kts"))
        if not (maven or gradle):
            raise SkipCandidate("no pom.xml or build.gradle at repo root")
        if gradle and not maven and not (baseline / "gradlew").exists():
            raise SkipCandidate("Gradle project without a wrapper")
        cfgs = ["pom.xml", "build.gradle", "build.gradle.kts"]
        text = " ".join((baseline / f).read_text(errors="replace") for f in cfgs
                        if (baseline / f).exists())
        jdk = java_major(text)
        classes = sorted({Path(t).stem for t in tests})
        sib_classes = sorted({Path(s).stem for s in siblings})
        if maven:
            mods = sorted({self.module_of(baseline, t, ("pom.xml",)) for t in tests + code} - {"."})
            pl = f"-pl {q([','.join(mods)])} -am " if mods else ""
            base = f"mvn -o -q -B {MVN_SKIPS} {pl}"
            flt = "-Dsurefire.failIfNoSpecifiedTests=false -DfailIfNoTests=false"

            def run(cls):
                return f"{base}test -Dtest={q([','.join(cls)])} {flt}"
            build = ["bash", "-c", f"{base}-DskipTests compile"]
            # Whole project first so the image doesn't single out the fixed module.
            warm = [f"(mvn -q -B {MVN_SKIPS} -DskipTests test-compile"
                    f" || mvn -q -B {MVN_SKIPS} {pl}-DskipTests test-compile)",
                    f"(mvn -q -B {MVN_SKIPS} test -Dtest=NoSuchTest__ {flt} || true)"]
            env = {"MAVEN_OPTS": "-Dmaven.repo.local=/opt/cache/m2"}
        else:
            mods = sorted({self.module_of(baseline, t, ("build.gradle", "build.gradle.kts"))
                           for t in tests + code} - {"."})
            prefix = [":" + m.replace("/", ":") for m in mods] or [""]
            g = "./gradlew --offline --no-daemon -q"

            def run(cls):
                sel = " ".join(f"--tests {q([c])}" for c in cls)
                return " && ".join(f"{g} {p}:test {sel}" for p in prefix)
            build = ["bash", "-c", " && ".join(f"{g} {p}:classes" for p in prefix)]
            warm = [GRADLE_RESOLVE,
                    "(./gradlew --no-daemon -q testClasses || "
                    + " && ".join(f"./gradlew --no-daemon -q {p}:testClasses" for p in prefix) + ")"]
            env = {"GRADLE_USER_HOME": "/opt/cache/gradle"}
        existing = ["bash", "-c", run(sib_classes)] if sib_classes else None
        return Plan(
            image=f"maven:3.9-eclipse-temurin-{jdk}",
            oracle=run(classes),
            compile_fail_re=r"COMPILATION ERROR|Compilation failure|compileTestJava FAILED|"
                            r"compileTestKotlin FAILED|cannot find symbol",
            build=build, existing=existing,
            agent_tests={},
            warm=warm, build_env=env,
            notes={"jdk": jdk, "build_tool": "maven" if maven else "gradle", "oracle_tests": classes},
        )


    def env_plan(self, baseline, code):
        maven = (baseline / "pom.xml").exists()
        gradle = any((baseline / f).exists() for f in ("build.gradle", "build.gradle.kts"))
        if not (maven or gradle):
            raise SkipCandidate("no pom.xml or build.gradle at repo root")
        if gradle and not maven and not (baseline / "gradlew").exists():
            raise SkipCandidate("Gradle project without a wrapper")
        cfgs = ["pom.xml", "build.gradle", "build.gradle.kts"]
        text = " ".join((baseline / f).read_text(errors="replace") for f in cfgs
                        if (baseline / f).exists())
        jdk = java_major(text)
        if maven:
            mods = sorted({self.module_of(baseline, c, ("pom.xml",)) for c in code} - {"."})
            pl = f"-pl {q([','.join(mods)])} -am " if mods else ""
            build = ["bash", "-c", f"mvn -o -q -B {MVN_SKIPS} {pl}-DskipTests compile"]
            flt = "-Dsurefire.failIfNoSpecifiedTests=false -DfailIfNoTests=false"
            warm = [f"(mvn -q -B {MVN_SKIPS} -DskipTests test-compile"
                    f" || mvn -q -B {MVN_SKIPS} {pl}-DskipTests test-compile)",
                    f"(mvn -q -B {MVN_SKIPS} test -Dtest=NoSuchTest__ {flt} || true)"]
            env = {"MAVEN_OPTS": "-Dmaven.repo.local=/opt/cache/m2"}
        else:
            mods = sorted({self.module_of(baseline, c, ("build.gradle", "build.gradle.kts"))
                           for c in code} - {"."})
            prefix = [":" + mm.replace("/", ":") for mm in mods] or [""]
            g = "./gradlew --offline --no-daemon -q"
            build = ["bash", "-c", " && ".join(f"{g} {pp}:classes" for pp in prefix)]
            warm = [GRADLE_RESOLVE,
                    "(./gradlew --no-daemon -q testClasses || "
                    + " && ".join(f"./gradlew --no-daemon -q {pp}:testClasses" for pp in prefix) + ")"]
            env = {"GRADLE_USER_HOME": "/opt/cache/gradle"}
        return Plan(
            image=f"maven:3.9-eclipse-temurin-{jdk}", oracle="",
            compile_fail_re=r"COMPILATION ERROR|Compilation failure|compileTestJava FAILED|"
                            r"compileTestKotlin FAILED|cannot find symbol",
            build=build, existing=None, agent_tests={}, warm=warm, build_env=env,
            notes={"jdk": jdk, "build_tool": "maven" if maven else "gradle",
                   "no_upstream_oracle": True},
        )


# ==================================================================== Rust

class RustAdapter(Adapter):
    name, track = "rust", "lang:rust"
    dep_files = ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml")

    # Only integration tests (tests/*.rs) can be an oracle: inline #[cfg(test)]
    # tests live inside the source files the reference patch changes.
    def is_test(self, p): return p.endswith(".rs") and (p.startswith("tests/") or "/tests/" in p)
    def is_source(self, p): return p.endswith(".rs")

    @staticmethod
    def crate_of(baseline: Path, path: str) -> str | None:
        d = Path(path).parent
        while True:
            ct = baseline / d / "Cargo.toml"
            if ct.exists():
                m = re.search(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', ct.read_text(errors="replace"),
                              re.M | re.S)
                return m.group(1) if m else None
            if d == Path("."):
                return None
            d = d.parent

    def plan(self, baseline, tests, code, test_diff, siblings):
        if not (baseline / "Cargo.toml").exists():
            raise SkipCandidate("no Cargo.toml at repo root")

        def run(files):
            parts = []
            for f in files:
                crate = self.crate_of(baseline, f)
                p = f"-p {q([crate])} " if crate else ""
                parts.append(f"cargo test --offline {p}--test {q([Path(f).stem])}")
            return " && ".join(parts)
        top = [t for t in tests if Path(t).parent.name == "tests"]
        if not top:
            raise SkipCandidate("Rust test changes are not top-level integration tests")
        sib_top = [s for s in siblings if Path(s).parent.name == "tests"][:10]
        crates = sorted({c for c in (self.crate_of(baseline, f) for f in tests + code) if c})
        p = " ".join(f"-p {q([c])}" for c in crates)
        existing = ["bash", "-c", run(sib_top)] if sib_top else None
        return Plan(
            image="rust:1-bookworm",
            oracle=run(top),
            compile_fail_re=r"error\[E[0-9]+\]|could not compile|no test target named",
            build=["bash", "-c", f"cargo build --offline {p}"],
            existing=existing,
            agent_tests={},
            warm=["cargo fetch", "(cargo test --no-run --workspace || true)"],
            build_env={"CARGO_TARGET_DIR": "/opt/cache/target", "CARGO_HOME": "/usr/local/cargo"},
            runtime_env={"CARGO_NET_OFFLINE": "true"},
            chown=["/usr/local/cargo"],
            notes={"crates": crates},
        )


    def env_plan(self, baseline, code):
        if not (baseline / "Cargo.toml").exists():
            raise SkipCandidate("no Cargo.toml at repo root")
        crates = sorted({c for c in (self.crate_of(baseline, f) for f in code) if c})
        pp = " ".join(f"-p {q([c])}" for c in crates)
        return Plan(
            image="rust:1-bookworm", oracle="",
            compile_fail_re=r"error\[E[0-9]+\]|could not compile|no test target named",
            build=["bash", "-c", f"cargo build --offline {pp}"], existing=None, agent_tests={},
            warm=["cargo fetch", "(cargo test --no-run --workspace || true)"],
            build_env={"CARGO_TARGET_DIR": "/opt/cache/target", "CARGO_HOME": "/usr/local/cargo"},
            runtime_env={"CARGO_NET_OFFLINE": "true"}, chown=["/usr/local/cargo"],
            notes={"crates": crates, "no_upstream_oracle": True},
        )


# ===================================================================== PHP

class PhpAdapter(Adapter):
    name, track = "php", "lang:php"
    dep_files = ("composer.json", "composer.lock")

    def is_test(self, p):
        return p.endswith("Test.php") or (p.endswith(".php") and (p.startswith("tests/") or "/tests/" in p))

    def is_source(self, p): return p.endswith(".php")

    def plan(self, baseline, tests, code, test_diff, siblings):
        cj = baseline / "composer.json"
        if not cj.exists():
            raise SkipCandidate("no composer.json at repo root")
        comp = json.loads(cj.read_text(errors="replace") or "{}")
        if "phpunit/phpunit" not in {**comp.get("require-dev", {}), **comp.get("require", {})}:
            raise SkipCandidate("composer.json has no phpunit")
        m = re.search(r"(\d+)\.(\d+)", str((comp.get("require") or {}).get("php", "")))
        want = (int(m.group(1)), int(m.group(2))) if m else (8, 2)
        ver = next((v for v in ((7, 4), (8, 0), (8, 1), (8, 2), (8, 3)) if v >= want), (8, 3))
        testf = [t for t in tests if t.endswith("Test.php")] or tests

        def run(files):
            return "rc=0; for f in " + q(files) + "; do vendor/bin/phpunit \"$f\" || rc=1; done; exit $rc"
        lint = "for f in " + q(code) + "; do php -l \"$f\" >/dev/null || exit 1; done"
        existing = ["bash", "-c", run([s for s in siblings if s.endswith("Test.php")])] \
            if any(s.endswith("Test.php") for s in siblings) else None
        return Plan(
            image=f"php:{ver[0]}.{ver[1]}-cli",
            oracle=f"bash -c {q([run(testf)])}",
            compile_fail_re=r"PHP Parse error|Parse error:|Class \"?[A-Za-z_\\]+\"? not found|Cannot open file",
            build=["bash", "-c", lint], existing=existing,
            agent_tests={},
            warm=["composer install --no-interaction --prefer-dist --no-progress"
                  " || composer install --no-interaction --prefer-dist --no-progress"
                  " --ignore-platform-reqs"],
            build_env={"COMPOSER_CACHE_DIR": "/opt/cache/composer", "COMPOSER_ALLOW_SUPERUSER": "1"},
            extra_apt=["unzip"],
            docker_prelude=["COPY --from=composer:2 /usr/bin/composer /usr/bin/composer"],
            notes={"php": f"{ver[0]}.{ver[1]}"},
        )


    def env_plan(self, baseline, code):
        cj = baseline / "composer.json"
        if not cj.exists():
            raise SkipCandidate("no composer.json at repo root")
        comp = json.loads(cj.read_text(errors="replace") or "{}")
        if "phpunit/phpunit" not in {**comp.get("require-dev", {}), **comp.get("require", {})}:
            raise SkipCandidate("composer.json has no phpunit")
        m = re.search(r"(\d+)\.(\d+)", str((comp.get("require") or {}).get("php", "")))
        want = (int(m.group(1)), int(m.group(2))) if m else (8, 2)
        ver = next((v for v in ((7, 4), (8, 0), (8, 1), (8, 2), (8, 3)) if v >= want), (8, 3))
        lint = "for f in " + q(code) + "; do php -l \"$f\" >/dev/null || exit 1; done"
        return Plan(
            image=f"php:{ver[0]}.{ver[1]}-cli", oracle="",
            compile_fail_re=r"PHP Parse error|Parse error:|Class \"?[A-Za-z_\\]+\"? not found|Cannot open file",
            build=["bash", "-c", lint], existing=None, agent_tests={},
            warm=["composer install --no-interaction --prefer-dist --no-progress"
                  " || composer install --no-interaction --prefer-dist --no-progress"
                  " --ignore-platform-reqs"],
            build_env={"COMPOSER_CACHE_DIR": "/opt/cache/composer", "COMPOSER_ALLOW_SUPERUSER": "1"},
            extra_apt=["unzip"],
            docker_prelude=["COPY --from=composer:2 /usr/bin/composer /usr/bin/composer"],
            notes={"php": f"{ver[0]}.{ver[1]}", "no_upstream_oracle": True},
        )


# ==================================================================== Ruby

class RubyAdapter(Adapter):
    name, track = "ruby", "lang:ruby"
    dep_files = ("Gemfile", "Gemfile.lock")

    def is_dep_file(self, p): return super().is_dep_file(p) or p.endswith(".gemspec")

    def is_test(self, p):
        return bool(re.search(r"(^|/)spec/.+_spec\.rb$|(^|/)test/.+(_test|/test_[^/]+)\.rb$", p))

    def is_source(self, p): return p.endswith(".rb")

    def plan(self, baseline, tests, code, test_diff, siblings):
        if not (baseline / "Gemfile").exists():
            raise SkipCandidate("no Gemfile at repo root")
        ver = "3.2"
        rv = baseline / ".ruby-version"
        m = re.search(r"(\d+)\.(\d+)", rv.read_text(errors="replace")) if rv.exists() else None
        if m:
            ver = f"{m.group(1)}.{m.group(2)}"
        tag = f"ruby:{ver}-bookworm" if ver >= "3.0" else f"ruby:{ver}-bullseye"
        rspec = all("_spec.rb" in t for t in tests)

        def run(files):
            if rspec:
                return f"bundle exec rspec {q(files)}"
            return ("rc=0; for f in " + q(files) +
                    "; do bundle exec ruby -Ilib -Itest \"$f\" || rc=1; done; exit $rc")
        lint = "for f in " + q(code) + "; do ruby -c \"$f\" >/dev/null || exit 1; done"
        existing = ["bash", "-c", run(siblings)] if siblings else None
        return Plan(
            image=tag,
            oracle=run(tests) if rspec else f"bash -c {q([run(tests)])}",
            compile_fail_re=r"SyntaxError|cannot load such file|LoadError|uninitialized constant",
            build=["bash", "-c", lint], existing=existing,
            agent_tests={},
            # Use the bundler version the lockfile was written with (old
            # projects fail under a modern bundler).
            warm=["v=$(awk '/BUNDLED WITH/{getline; print $1}' Gemfile.lock 2>/dev/null); "
                  "if [ -n \"$v\" ] && gem install bundler -v \"$v\" --no-document; "
                  "then bundle _${v}_ install --jobs 4; else bundle install --jobs 4; fi"],
            build_env={"BUNDLE_PATH": "/opt/cache/bundle"},
            notes={"ruby": ver, "runner": "rspec" if rspec else "minitest"},
        )


    def env_plan(self, baseline, code):
        if not (baseline / "Gemfile").exists():
            raise SkipCandidate("no Gemfile at repo root")
        ver = "3.2"
        rv = baseline / ".ruby-version"
        m = re.search(r"(\d+)\.(\d+)", rv.read_text(errors="replace")) if rv.exists() else None
        if m:
            ver = f"{m.group(1)}.{m.group(2)}"
        tag = f"ruby:{ver}-bookworm" if ver >= "3.0" else f"ruby:{ver}-bullseye"
        lint = "for f in " + q(code) + "; do ruby -c \"$f\" >/dev/null || exit 1; done"
        return Plan(
            image=tag, oracle="",
            compile_fail_re=r"SyntaxError|cannot load such file|LoadError|uninitialized constant",
            build=["bash", "-c", lint], existing=None, agent_tests={},
            warm=["v=$(awk '/BUNDLED WITH/{getline; print $1}' Gemfile.lock 2>/dev/null); "
                  "if [ -n \"$v\" ] && gem install bundler -v \"$v\" --no-document; "
                  "then bundle _${v}_ install --jobs 4; else bundle install --jobs 4; fi"],
            build_env={"BUNDLE_PATH": "/opt/cache/bundle"},
            notes={"ruby": ver, "runner": "rspec", "no_upstream_oracle": True},
        )


ADAPTERS: dict[str, Adapter] = {a.name: a for a in (
    GoAdapter(), PythonAdapter(), JavaScriptAdapter(), JavaAdapter(), RustAdapter(),
    PhpAdapter(), RubyAdapter(), *SETUP_ADAPTERS)}
