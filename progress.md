# Pseudo-Probes with Stable GUIDs — Progress

**Goal:** enable pseudo-probe / CSSPGO in environments where
`-funique-internal-linkage-names` cannot be used, by giving same-named
internal-linkage (`static`) functions **unique, stable GUIDs without renaming
the symbol**. Opt-in via `-fpseudo-probe-use-stable-guid`.

**Branch:** `pseudo-probes-use-stable-guid` (base: `origin/main`, has `39dcb0ff`
metadata-GUID infra).
**Design doc:** `design.md` (in repo root).

---

## Core principle

> Assign the GUID once (`AssignGUIDPass` → `!guid` = `MD5("sourcefile;name")`
> for locals), carry it into every representation, and have every consumer
> **read** it — never recompute from a name.

Everything below is **flag-gated**: with the flag off, output is byte-identical
to today (verified across the SampleProfile + profdata suites).

---

## Status by area

| Area | Status |
|---|---|
| DWARF `DW_AT_LLVM_guid` (offline binding, Variant A) | ✅ committed |
| clang `-fpseudo-probe-use-stable-guid` (driver + cc1, suppresses unique-names) | ✅ committed |
| `PseudoProbeInserter` callsite GUID (read from block probe) | ✅ committed |
| `AssignGUIDPass` wiring on the probe path | ✅ committed (Prototype) |
| Prober + descriptor use `F.getGUID()` | ✅ committed (Prototype) |
| Inline-tree GUIDs (`PseudoProbePrinter`, `DISubprogram→GUID` from block probes) | ✅ committed (Prototype) |
| Profile format `SecFlagStableGUID` + `ProfileUsesStableGUID` (reader/writer) | ✅ committed (Prototype) |
| Use-time matcher `getSamplesFor` keys by GUID | ✅ committed (Prototype) |
| ExtBinary lazy-load `FuncOffsetTable` keyed by GUID | ✅ committed (Prototype) |
| `llvm-profdata merge --stable-guid` (testing/opt-in) | ✅ committed (Prototype) |
| Stale-profile matcher GUID anchors (`SampleProfileMatcher`) + `SymbolMap` | ✅ committed (`matcher`) |
| Full count *annotation* through inlined-frame lookup (`findFunctionSamples` inline-stack walk) | ✅ committed |
| `llvm-profgen --stable-guid` (extbinary numeric + `name;guid` text) | ✅ committed |
| `llvm-profdata show` stable-guid section-flag label | ✅ committed |
| `-ffile-prefix-map` robustness (Variant B) | ❌ out of scope (see below) |

---

## Commit stack (oldest → newest)

- `b5bf06eb749c` **[DWARF] add DW_AT_LLVM_guid tag** — vendor attr `0x3e16`,
  emitted per subprogram-definition DIE (`DwarfCompileUnit::updateSubprogramScopeDIE`)
  as `DW_FORM_data8` = `F.getGUIDOrFallback()`, gated on `llvm.pseudo_probe_desc`.
  Tests: `DebugInfo/{X86,AArch64}/DW_AT_LLVM_guid.ll`.
- `a1cc23439464` **[clang] -fpseudo-probe-use-stable-guid** — `BoolFOption` +
  `CodeGenOpts.PseudoProbeUseStableGUID`; driver suppresses the implicit
  `-funique-internal-linkage-names` when stable GUIDs are requested.
  Test: `clang/test/Driver/pseudo-probe.c`.
- `5435912df332` **[PseudoProbe] Read callsite probe GUID from the function's own
  block probe** — `PseudoProbeInserter` was recomputing `MD5(name)` for callsite
  probes; now reads the owner GUID from the function's block probe (keyed by
  `DISubprogram`). Standalone correctness fix.
  Test: `CodeGen/X86/pseudo-probe-callsite-guid.ll`.
- `9569b965ca57` **Prototype** — the P1 producer + use-time bundle:
  - `AssignGUIDPass` scheduled before the prober at both O0/O1+ points
    (`PassBuilderPipelines.cpp`), driven by `PGOOptions.PseudoProbeUseStableGUID`
    (set from `CodeGenOpts` in `BackendUtil.cpp`).
  - Prober intrinsic + descriptor use `F.getGUIDIfAssigned()` (fallback to name
    hash) — `SampleProfileProbe.cpp`.
  - Inline-tree caller GUIDs: `PseudoProbePrinter` builds a per-MF
    `DISubprogram→GUID` map from **block** probes and reads it (works across
    ThinLTO where the callee Function is gone but its probe+DISubprogram survive).
  - Profile format: `SecFlagStableGUID` + `FunctionSamples::ProfileUsesStableGUID`
    (`SampleProf.h/.cpp`, reader, writer).
  - Use-time matcher: `getSamplesFor(const Function&)` keys by
    `F.getGUIDOrFallback()`; ExtBinary lazy-load collects stable GUIDs
    (`FuncGuidsToUse`) so the GUID-keyed `FuncOffsetTable` resolves internal
    functions.
  - `llvm-profdata merge --stable-guid` sets the flag (enables producing stable
    profiles for testing).
  - Tests: `clang/test/CodeGen/pseudo-probe-stable-guid*.c` (+ inline/callsite/
    thinlto + Inputs), `Transforms/SampleProfile/pseudo-probe-stable-guid.ll`,
    `unittests/ProfileData/SampleProfTest.cpp` (flag round-trip).

## Staged (uncommitted) — stale-profile matcher

- `llvm/lib/Transforms/IPO/SampleProfileMatcher.cpp` — `findIRAnchors` emits GUID
  callee anchors in stable mode (direct call: `Callee->getGUIDOrFallback()`;
  inlined callsite: recovered via `M->getFunction`). Fixed `FunctionId::stringRef()`
  asserts on GUID (hashcode) anchors: `getFilteredAnchorList`/assert use
  `empty()`, debug print uses `operator<<`, callee resolution uses the GUID-keyed
  `SymbolMap`.
- `llvm/lib/Transforms/IPO/SampleProfile.cpp` — `SymbolMap` also maps
  `FunctionId(F->getGUIDOrFallback()) → F`.
- Tests: `Transforms/SampleProfile/pseudo-probe-stale-profile-matching-guid.ll`
  (+ `.prof`).
- **Committed** as `2aef715af3ee` ("matcher").

## Commit: inlined-frame count annotation

- `dd6cdf7e192a` **[SampleProfile] Attribute counts to inlined statics via stable
  GUID** — the inline-stack walk (`FunctionSamples::findFunctionSamples(DILocation*)`)
  keyed each inlined callee frame by `MD5(name)`, missing stable-GUID-keyed profile
  nodes for inlined statics. Now the loader builds a `DISubprogram → GUID` map from
  every **block** pseudo probe in the module (operand 0 = authoritative GUID, travels
  with the inlined body, survives ThinLTO), threads it into the walk, and keys each
  inlined frame by its stable GUID via a new
  `findFunctionSamplesAt(Loc, FunctionId)` overload. Gated on `ProfileUsesStableGUID`;
  name path unchanged otherwise.
  - Why not rederive from the `DISubprogram`'s `DIFile`: proven divergent —
    `-ffile-prefix-map` remaps the DWARF path but not `source_filename`
    (`MD5("/abs/helper.c;helper")` ≠ `MD5("./helper.c;helper")`), and cross-module
    ThinLTO carries the *callee's* file, not the importing module's `source_filename`.
  - Test: `Transforms/SampleProfile/pseudo-probe-stable-guid-inline-count.ll` (+
    `.prof`). Negative control verified: an inlined node keyed by `MD5("helper")`
    yields 1 AppliedSamples remark (caller only); keyed by the stable GUID yields 3
    (caller probe 1 = 1000, inlined helper probes 1 & 4 = 200 each).

---

## Verified end-to-end

- **Disambiguation:** two `static helper` in different TUs get distinct stable
  GUIDs (ThinLTO), no symbol renaming.
- **Inline consistency:** a static's own probe GUID == its GUID as an inline
  frame — across single-module, ThinLTO cross-module inline-through, and FullLTO
  (both inlined and standalone copies).
- **Callsite probes:** block + callsite probes of a static share the stable GUID.
- **Sample loader:** a `static` matches its profile entry by GUID
  (`getSamplesFor`), where name-keying misses.
- **Stale matching:** a stale profile's static callsite anchor is matched via its
  stable GUID (`Callsite with callee:<GUID> is matched`); name-keying leaves it
  a non-anchor.
- **llvm-profdata show / text round-trip:** stable-GUID profiles display and
  round-trip (numeric GUID keys).

---

## Remaining work

1. **`llvm-profgen` auto-detection** — `--stable-guid` is currently explicit. Could
   auto-detect stable-GUID binaries (e.g. a marker in `llvm.pseudo_probe_desc` /
   `DW_AT_LLVM_guid` presence) so the flag isn't needed. Minor ergonomics.
2. **`hwtrace-profgen`** — the ETM/hwtrace path shares `ProfileGeneratorBase`, so
   `--stable-guid` already flows through; verify with a hwtrace fixture.
3. **Upstreaming** — split into reviewable PRs; the callsite-GUID fix
   (`5435912df332`) stands alone.

## Completed: profgen opt-in (commits `a6c878b6999d`, `23afab7b4301`)

- **Key realization:** the binary `.pseudo_probe` section decoded by
  `MCPseudoProbeDecoder` is *already* a GUID-keyed inline forest
  (`InlineSite = <GUID, ProbeID>`); the emitted profile only became name-keyed
  because `ProfiledBinary::getInlineContextForProbe` stringified each frame's GUID
  back to `FuncName`. The fix was "stop stringifying the GUID you already have."
- `llvm-profgen --stable-guid`: keys each context frame by its authoritative GUID
  and sets `ProfileUsesStableGUID` (writer stamps `SecFlagStableGUID`). The
  profgen-internal `MCPseudoProbeFrameLocation` was extended to carry the frame
  GUID (no on-disk format change).
- **extbinary** (`--use-md5`, the CSSPGO-consumed form): numeric GUID keys.
- **text**: readable `name;guid` (GUID authoritative, name a label); reader parses
  the `;guid` suffix, keys by GUID, self-detects stable mode (text has no section
  flag). profgen attaches a GUID→name map from descriptors so the inline tree
  prints readably.
- `llvm-profdata show --show-sec-info-only` now prints `stable-guid`.
- Tests: `tools/llvm-profgen/stable-guid.test`,
  `tools/llvm-profdata/sample-stable-guid-text.test`.

## Known limitations / decisions

- **`-ffile-prefix-map`** remaps DWARF paths but NOT `source_filename`, so
  DWARF-rederivation (Variant B) is unsafe. **Decision:** ship Variant A
  (`DW_AT_LLVM_guid`), which reads the stamped GUID and sidesteps this. Not
  worrying about prefix-map for now (per direction).
- **Carrier for inline-frame GUIDs:** the GUID is carried on a first-class
  **`DISubprogram::guid` field** (commit `6c8f38e9`), stamped by `AssignGUIDPass`
  and read via `SP->getGuid()` by every consumer (DWARF emission, probe printer,
  probe inserter, sample-loader inline walk, stale matcher). This replaced the
  earlier approach of reconstructing a `DISubprogram→GUID` map by scanning block
  probes in three separate places. The field survives ThinLTO/DCE because the
  `DISubprogram` is kept alive by the inlined instructions even after the callee
  `Function` is gone. `DW_AT_LLVM_guid` is now just the DWARF projection of this
  field, emitted only for internal-linkage functions (commit `7fe9f59f`) — a net
  space win over `-funique-internal-linkage-names`.
- **Why not recompute from the `DISubprogram`'s `DIFile`:** the `DIFile` names
  where the *text* lives (for a header-static, the shared header — identical
  across every TU that includes it), while the GUID needs the origin *TU's*
  `source_filename`; these differ for any header-defined static, so recomputing
  from `DIFile` collapses distinct statics into one wrong identity (worse under
  ThinLTO, where the imported `DIFile` points at an absent module). The GUID must
  be carried, not recomputed.
- **Same source path + different `-D`** still collides (shared with
  `-funique-internal-linkage-names`; no regression).

---

## How to reproduce the tests

```
# unit + lit
build/bin/llvm-lit llvm/test/Transforms/SampleProfile/ llvm/test/tools/llvm-profdata/ \
  clang/test/CodeGen/pseudo-probe-stable-guid*.c clang/test/Driver/pseudo-probe.c \
  llvm/test/DebugInfo/{X86,AArch64}/DW_AT_LLVM_guid.ll
build/unittests/ProfileData/ProfileDataTests --gtest_filter='SampleProfTest.*'
```

Only known failure: `Transforms/SampleProfile/pseudo-probe-emit-macho.ll` —
**pre-existing, unrelated** (MachO `__PSEUDO_PROBE` vs `__LLVM`/`__probes`
segment naming from the dsymutil-collect-probes rework).
