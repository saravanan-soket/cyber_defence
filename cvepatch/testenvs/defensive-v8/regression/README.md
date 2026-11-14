# Trusted regression test (operator-supplied)

bench-v8 does not ship one. Put the per-CVE regression check here as
`run.sh` before building the defensive image. Contract (read by the trusted
grader, never shown to the agent):

- runs the rebuilt `out/x64.release-asan/d8` from the current working dir
  (`/rlenv/source/v8` checkout under test);
- exits **non-zero on the vulnerable baseline** (ASan report / crash) and
  **0 on a correctly patched tree**;
- deterministic, no network, finishes within the manifest `timeout_s`.

A natural source is the regression test V8 itself landed with the fix commit
(usually under `test/mjsunit/regress/`). Record its provenance (commit +
sha256) in the task manifest `evidence`.
