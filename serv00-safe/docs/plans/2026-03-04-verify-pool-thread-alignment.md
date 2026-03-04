# Verify Pool Thread Alignment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make verify worker count follow configured threads (with cap), remove redundant pre-connect checks, and stop duplicate XUI fingerprint probes.

**Architecture:** Reuse existing scanner threading model and only adjust verify pool startup input, worker flow, and verify logic guard conditions. Keep current hard cap (`VERIFY_POOL_MAX`) and existing queue/worker lifecycle intact. Avoid unrelated behavior changes.

**Tech Stack:** C (pthread/_beginthreadex), existing scanner pipeline in `project/scanner.c`

---

### Task 1: Align verify pool size with configured threads

**Files:**
- Modify: `project/scanner.c`

**Step 1: Write the failing test**

Create/extend a small scanner unit test (or harness) that sets `g_config.threads` to a non-8 value and asserts verify pool startup receives that value before clamping.

**Step 2: Run test to verify it fails**

Run: build/test command used in this repo for scanner tests (or a temporary harness compile command)
Expected: verify pool currently starts with fixed `8`.

**Step 3: Write minimal implementation**

Change verify pool startup call sites from fixed `8` to `g_config.threads`; keep `scanner_start_verify_pool()` clamping to `[1, VERIFY_POOL_MAX]`.

**Step 4: Run test to verify it passes**

Run the same test command.
Expected: verify pool input matches configured threads; effective pool size is clamped by `VERIFY_POOL_MAX`.

**Step 5: Commit**

```bash
git add project/scanner.c
git commit -m "fix: align verify pool startup with configured thread count"
```

### Task 2: Remove redundant worker pre-connect check

**Files:**
- Modify: `project/scanner.c`

**Step 1: Write the failing test**

Add/extend a harness to count socket connect attempts per target path and assert no extra connect happens before fingerprint/verify path.

**Step 2: Run test to verify it fails**

Run the relevant test/harness command.
Expected: one extra connection from `worker_thread` pre-check.

**Step 3: Write minimal implementation**

Delete the initial `socket_create` + `socket_connect_timeout` + close block in `worker_thread`; keep existing mode/fingerprint logic unchanged.

**Step 4: Run test to verify it passes**

Run the same test/harness command.
Expected: extra connect attempt removed; pipeline still processes targets normally.

**Step 5: Commit**

```bash
git add project/scanner.c
git commit -m "perf: remove redundant worker pre-connect path"
```

### Task 3: Remove duplicate XUI fingerprint check in verify logic

**Files:**
- Modify: `project/scanner.c`

**Step 1: Write the failing test**

Add/extend a harness where `verify_task_t.xui_fingerprint_ok` is already set and assert no secondary `xui_has_required_fingerprint()` call is made in `scanner_run_verify_logic`.

**Step 2: Run test to verify it fails**

Run the test/harness command.
Expected: duplicate call occurs in current verify logic for negative state.

**Step 3: Write minimal implementation**

Remove the fallback block that re-runs `xui_has_required_fingerprint()` in `scanner_run_verify_logic`; consume precomputed fingerprint fields from task.

**Step 4: Run test to verify it passes**

Run the same test/harness command.
Expected: no duplicate XUI fingerprint call; verify behavior still respects fingerprint flags.

**Step 5: Commit**

```bash
git add project/scanner.c
git commit -m "perf: avoid duplicate xui fingerprint probes in verify stage"
```

### Task 4: End-to-end regression verification

**Files:**
- Modify: `project/scanner.c` (if any follow-up fix needed)

**Step 1: Run compile/build check**

Run: project build command for Linux target (and Windows if available).
Expected: build succeeds without new warnings/errors in touched areas.

**Step 2: Run scan smoke check**

Run a short scan smoke command with small target set and custom `threads` value.
Expected: scanning works, verify pool starts with configured threads capped by `VERIFY_POOL_MAX`, no crashes/hangs.

**Step 3: Commit final follow-up (if needed)**

```bash
git add project/scanner.c
git commit -m "fix: stabilize scanner pipeline after verify-thread alignment"
```
