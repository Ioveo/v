# Two-Stage Verify Upgrade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a two-stage workflow where stage2 verification can consume standardized stage1 results directly, with source and verify-scope selection in submenu.

**Architecture:** Stage1 writes normalized candidate records (`ip:port|type=...|source=stage1`). Stage2 reads from either those records or custom-upload source, materializes scanner inputs, and runs scope-specific verification mode (all/xui/s5).

**Tech Stack:** C, existing scanner pipeline (`scanner_start_streaming`), JSON config in `config.c`, interactive menu in `missing_functions.c`.

---

### Task 1: Persist stage2 source/scope config

**Files:**
- Modify: `saia.h`
- Modify: `config.c`

**Step 1: Write the failing test**

Manual repro: set verify source/scope in submenu, restart program, value is lost.

**Step 2: Run test to verify it fails**

Run: start program -> set values -> restart -> inspect values.
Expected: values reset unexpectedly.

**Step 3: Write minimal implementation**

- Add `verify_source`, `verify_filter` to `config_t`.
- Set defaults in `config_init_defaults`.
- Load/save fields in `config_load` and `config_save`.

**Step 4: Run test to verify it passes**

Run same repro.
Expected: values persist.

**Step 5: Commit**

```bash
git add saia.h config.c
git commit -m "feat: persist stage2 verify source and scope settings"
```

### Task 2: Add verify source/scope submenu controls

**Files:**
- Modify: `missing_functions.c`

**Step 1: Write the failing test**

Manual repro: mode=verify has no source/scope options.

**Step 2: Run test to verify it fails**

Run: enter option1 start submenu with verify mode.
Expected: missing source/scope prompts.

**Step 3: Write minimal implementation**

- In start submenu, when mode=4, prompt:
  - verify scope: all/xui/s5
  - source: stage1/custom(13)
- Persist values to config.

**Step 4: Run test to verify it passes**

Run submenu again.
Expected: prompts exist and values save.

**Step 5: Commit**

```bash
git add missing_functions.c
git commit -m "feat: add stage2 source and scope selection in start submenu"
```

### Task 3: Standardize stage1 candidate output

**Files:**
- Modify: `scanner.c`

**Step 1: Write the failing test**

Manual repro: stage1 found lines cannot be consumed as stable machine format.

**Step 2: Run test to verify it fails**

Run: stage1 scan with XUI/S5 hits.
Expected: no normalized candidate file.

**Step 3: Write minimal implementation**

- On `[XUI_FOUND]` / `[S5_FOUND]`, append standardized line to `base_dir/stage1_candidates.list`:
  - `ip:port|type=xui|source=stage1`
  - `ip:port|type=s5|source=stage1`

**Step 4: Run test to verify it passes**

Run same scan.
Expected: standardized lines generated.

**Step 5: Commit**

```bash
git add scanner.c
git commit -m "feat: emit normalized stage1 candidates for stage2"
```

### Task 4: Build stage2 materialization from stage1/custom

**Files:**
- Modify: `main.c`

**Step 1: Write the failing test**

Manual repro: verify mode cannot directly consume stage1 source with scope filtering.

**Step 2: Run test to verify it fails**

Run: verify mode source=stage1, scope=xui/s5.
Expected: no direct stage1-driven execution path.

**Step 3: Write minimal implementation**

- Add helper(s) to parse candidate lines and filter by scope.
- Materialize to:
  - `stage2_nodes.list` (unique IP)
  - runtime port list (unique ports)
- For source=custom use option13 input directly.
- Map scope to runtime mode: all->deep, xui->xui, s5->s5.

**Step 4: Run test to verify it passes**

Run verify-mode flows for source1/source2 with all three scopes.
Expected: stage2 starts with correct source and mode mapping.

**Step 5: Commit**

```bash
git add main.c
git commit -m "feat: enable stage2 verification from stage1 or custom source"
```

### Task 5: Final verification and push

**Files:**
- Inspect: `main.c`, `missing_functions.c`, `scanner.c`, `config.c`, `saia.h`

**Step 1: Write the failing test**

N/A

**Step 2: Run test to verify it fails**

Run: project compile command + basic flow smoke checks.
Expected: any compile/runtime issue surfaces here.

**Step 3: Write minimal implementation**

- Fix only blocking regressions.

**Step 4: Run test to verify it passes**

Run same compile/smoke checks.
Expected: no blocking regression in two-stage workflow.

**Step 5: Commit**

```bash
git add main.c missing_functions.c scanner.c config.c saia.h
git commit -m "fix: finalize two-stage verify workflow integration"
```
