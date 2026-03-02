# Two-Stage Verify Design

## Goal

Add a low-load two-stage workflow where stage 2 verification can directly consume normalized outputs from stage 1, with selectable verification scope (all/XUI/S5) and selectable source (stage1/custom upload).

## User-Facing Behavior

- In start submenu when mode=verify:
  - `验真范围`: `1 全部` / `2 仅XUI` / `3 仅S5`
  - `验真来源`: `1 第一阶段结果` / `2 自定义上传(13)`
- Source 1:
  - Build stage2 candidates from standardized stage1 records.
  - Convert to scanner-consumable nodes + port set automatically.
- Source 2:
  - Use custom uploaded targets from option 13.
  - Verify scope still applies (all/XUI/S5).

## Standardized Stage1 Format

Stage1 will append machine-readable candidate records to:

- `base_dir/stage1_candidates.list`

Record format:

- `ip:port|type=xui|source=stage1`
- `ip:port|type=s5|source=stage1`

Only `[XUI_FOUND]` and `[S5_FOUND]` are standardized into this file.

## Stage2 Data Pipeline

For source=stage1:

1. Read `stage1_candidates.list` (fallback parse from report if missing).
2. Filter by verify scope.
3. Materialize:
   - `base_dir/stage2_nodes.list` (unique IPs)
   - dynamic port list (unique ports) for this run
4. Run scanner with selected verification scope mapped to runtime mode:
   - all -> deep
   - xui -> xui
   - s5 -> s5

For source=custom:

- Use uploaded targets from option 13 directly.
- Apply same verify scope mapping.

## Config Additions

- `verify_source` (1=stage1, 2=custom)
- `verify_filter` (1=all, 2=xui, 3=s5)

Persist in config file and load defaults safely.

## Safety / Compatibility

- Existing panel/TG display format unchanged.
- Existing report lines preserved.
- If stage1 source has no candidates after filter, abort with clear hint.
