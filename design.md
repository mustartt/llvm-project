# Pseudo-Probes Without `-funique-internal-linkage-names` — Finalized Design

**Status:** finalized design
**Base:** `origin/main` (has commit `39dcb0ff` "Compute GUIDs once and store in metadata" — the metadata-GUID infrastructure). Note: the dsymutil pseudo-probe-collection work lives on branch `dsymutil-collect-probes` and must be merged with this.
**Goal:** enable pseudo-probe / CSSPGO in environments where `-funique-internal-linkage-names` cannot be used (it rewrites the symbol name), without losing the ability to disambiguate same-named internal-linkage (`static`) functions across translation units.

---

## 1. Problem

Pseudo-probe identity is name-string based. Producer and every consumer compute a function's GUID as `MD5(name)` (`getGUIDAssumingExternalLinkage`), where `name` is the debug linkage name. Two `static foo` in different TUs both hash to `MD5("foo")` and **collide**, so their profiles merge.

`-funique-internal-linkage-names` fixes this by mutating the *symbol* to `foo.__uniq.<hash>` before probes are emitted, so the names (and thus MD5s) differ. Where that flag is unavailable (symbol/ABI/tooling constraints), we need another way to get **unique GUIDs without renaming the symbol**.

## 2. Core principle

> **Assign the GUID once, carry it into every representation, and have every consumer *read* it — never recompute it from a name.**

Every failure mode of the name-based scheme (cross-TU collision, inline-context divergence, path-normalization contracts, offline join hazards) is an artifact of *recomputation*. Making the GUID authoritative stored data eliminates the class.

## 3. The GUID

Use the **stable metadata GUID** (commit `39dcb0ff`, present on `origin/main`):

- `GlobalValue::assignGUID()` computes `MD5(getGlobalIdentifier())` once and caches it in `!guid` metadata (`MD_unique_id`). `getGUID()` reads the cache (`Globals.cpp` ~104). `getGUIDIfAssigned()` (`GlobalValue.h:642`) returns `nullopt` when unset.
- For **local linkage**, `getGlobalIdentifier()` prepends the module source file: `"<Module::getSourceFileName()>;<name>"` (`Globals.cpp:170-197`). So a `static foo` in `a.c` gets `MD5("a.c;foo")` — **unique across TUs with the symbol still named `foo`.**
- `AssignGUIDPass` (`Utils/AssignGUID.cpp`) assigns GUIDs early; it is idempotent. It must run **before** probe emission whenever pseudo-probes are enabled (today it is only wired onto the ctxprof path).

The GUID derivation is now decoupled from consumers: it can later evolve (e.g. fold in a content/build hash to fix the residual `-D` collision, §12) with zero consumer changes.

## 4. Carrying the GUID

The GUID must be available at **five** points; three of them (inline tree, DWARF emission, stale-match anchors for inlined frames) have only debug info, not a `Function`. Therefore the GUID is carried on the **`DISubprogram`**, in addition to `!guid`:

```
AssignGUIDPass ──▶ !guid on Function
       │
       ├─ stamp ─▶ DISubprogram.GUID  (new field)
       │             └─ survives inlining: DILocation→getScope()→getSubprogram()
       │                stays alive even after the inlined callee Function is deleted
       │
       └─ (offline) ─▶ DWARF  (see §9)

Consumers READ (never recompute):
  • use-time matcher (§6)      → F.getGUID()
  • inline-tree probe emit (§5)→ callee DISubprogram.GUID
  • stale-match anchors (§7)   → callee DISubprogram.GUID / F.getGUID()
  • offline binding (§9)       → DWARF (Variant A reads it; Variant B rederives)
```

A first-class `DISubprogram` GUID field is the chosen carrier because it is the one thing reachable at all debug-info-only points **and** it is what naturally flows into DWARF. (`DISubprogram` already carries scalar fields like `Line`/`SPFlags`, so this is structurally consistent; it touches IR/bitcode/verifier/LangRef/AsmParser.)

## 5. Producer changes (three points, must agree)

All three currently hash the debug linkage name; all three switch to the stamped GUID:

1. **Probe intrinsic** — `SampleProfileProbe.cpp:349-353` → use `F.getGUID()`.
2. **Descriptor** — `createPseudoProbeDesc` (`MDBuilder.cpp:351-359`) → carry `F.getGUID()`.
3. **Inline-tree caller GUIDs** — `PseudoProbePrinter.cpp:49-56` currently does `getGUIDAssumingExternalLinkage(InlinedAt->getSubprogramLinkageName())`; switch to the callee `DISubprogram`'s stamped GUID (reachable from the `DILocation`). **This is mandatory** — otherwise the top-level GUID (`MD5("a.c;foo")`) disagrees with the inline-context GUID (`MD5("foo")`) for the same function, silently corrupting context profiles.

## 6. Use-time matcher

The loader must key each IR function to its profile entry by GUID, not name. Gated on the new profile flag (§8); flag off → existing name path runs verbatim.

- `getSamplesFor(F)` (`SampleProfReader.h:519-545`) → `Profiles.find(FunctionId(F.getGUID()))` instead of building the key from `getCanonicalFnName(F)`. (`FunctionId` accepts a raw `uint64`; the map keys on `getHashCode()`.)
- `SymbolMap` population (`SampleProfile.cpp:2187-2203`) → key by `F.getGUID()`.
- Name→GUID sites that hold a `Function` → `F.getGUID()`: `SampleProfile.cpp:363/375, 951, 1039, 2285`. Callee identities that come from the profile are already GUIDs in MD5 mode — use them directly.
- The on-demand `FuncOffsetTable` is **already** GUID-keyed (`SampleProfReader.h:961-965`) — no change.
- Probe path `ProbeManager->getDesc(FS.getGUID())` (`SampleProfile.cpp:2106`) is already GUID-side — no change.

## 7. Stale-profile matcher (must be preserved)

`SampleProfileMatcher` anchors on **`FunctionId`** (callee identity) and LCS-matches by `getHashCode()` (`SampleProfileMatcher.cpp:219-221`). It is *not* intrinsically name-based — names are just how the IR side currently populates the anchor:

- IR-side anchors: direct call `FunctionId(getCanonicalFnName(Callee->getName()))` (`:93`), inlined callsite `FunctionId(PrevDIL->getSubprogramLinkageName())` (`:86-87`).
- Profile-side anchors are already GUIDs in MD5 mode (`:147-149`).

**Fix:** populate the IR-side anchor with the **GUID** — `Callee->getGUID()` for direct calls, the callee `DISubprogram`'s stamped GUID for inlined callsites. The LCS and everything else are untouched. This rides on the same §4 `DISubprogram` GUID plumbing — no third mechanism. Bonus: GUID anchors **disambiguate same-named statics**, which name anchors cannot, so stale matching becomes *more* accurate for exactly the internal-linkage case we care about.

## 8. Profile format

No per-record byte-layout change. Changes are metadata-level:

- **New summary flag** `SecFlagStableGUID = (1 << 3)` in `SecProfSummaryFlags` (bit 3 is free). Signals "keys are stable metadata GUIDs, not `MD5(name)`," so the matcher keys by `F.getGUID()` and old `MD5(name)` profiles are not silently mixed with new binaries.
- **New global** `FunctionSamples::ProfileUsesStableGUID` (next to `ProfileIsProbeBased`, `SampleProf.h:1323`); writer sets the flag (mirror `SampleProfWriter.cpp` `addSectionFlag(SecProfSummary, …)`), reader reads it (mirror `SampleProfReader.cpp` `hasSecFlag`), `llvm-profgen` sets it where it sets `ProfileIsProbeBased`.
- **MD5/GUID keying is mandatory** (already the CSSPGO default). Uniqueness lives in the GUID; the **source path never enters the profile**.
- **`HasUniqSuffix` / `.__uniq.` stripping becomes dead** and is retired for these profiles.
- Contexts (CSSPGO) are unchanged — `(GUID, probe-id)` stacks.

### Text format

The text format is ours to extend, so internal symbols stay readable. **Chosen: `name@guid`** — the GUID is the authoritative key, the name is a decorative label:

```
compute@15822663052811949562:2000:0
 1: 2000
 2: 2000 helper@6699318081062747564:1800
helper@6699318081062747564:1800:200        ; readable "helper" + unique guid
 1: 1800
```

- The reader parses `name` + `guid`, keys on `FunctionId(guid)`, keeps `name` for display. Small reader/writer change.
- **Delimiter note:** `@` is already the CS context-frame separator (`[a @ b]`), so scope the `@guid` parse to the function-id token or pick a non-conflicting delimiter.
- This keeps the GUID decoupled from the name (future-proof if the derivation stops being name-based) and restores readable `llvm-profdata show` / `--function=<name>` output.
- **Interim alternative (no parser change):** write the file-qualified identifier as the name — `a.c;helper:1800:200`. The reader already hashes the name (`FunctionId::getHashCode` = `MD5Hash(string)`, `FunctionId.h:88-91`), so `MD5("a.c;helper")` *is* the GUID. Readable and unique, but re-couples identity to the name derivation.

### `llvm-profdata`

- **Display:** works as-is — it already prints numeric identities for MD5 profiles (`FunctionId::toString`, `FunctionId.h:63-66`); with `name@guid` it prints the readable name.
- **`--function=<name>` filter** (`llvm-profdata.cpp:932-944`) hashes the bare name and won't match `MD5("a.c;foo")` for statics; with `name@guid` the label match works, otherwise filter by GUID. Minor.
- **`merge`** must refuse/warn on `SecFlagStableGUID` mismatch (incompatible keyspaces). Small, necessary.

## 9. Offline binding — TWO variants

The probe section is GUID-keyed with relative address deltas; sentinel probes carry a GUID, not an address (`MCPseudoProbe.cpp:88-90`). So the offline tool (`llvm-profgen`, libhwtrace) must obtain `GUID → load address` externally. Both variants below produce that mapping; **pick one**, and the other is the fallback if the first is not accepted upstream. Everything in §3–§8 is identical regardless of the choice.

### Variant A (preferred): emit the GUID as a DWARF vendor attribute

The compiler stamps the function's GUID onto its DWARF subprogram DIE; the offline tool reads `GUID + low_pc` directly.

- **Define:** one line in `Dwarf.def`, next free LLVM vendor slot after `0x3e14`:
  `HANDLE_DW_AT(0x3e15, LLVM_guid, 0, LLVM)`. `llvm-dwarfdump` prints it for free (table-driven `AttributeString`, `Dwarf.cpp:72`). Vendor range `DW_AT_lo_user`..`hi_user` needs no DWARF-committee standardization. (Named generically — it carries the GlobalValue GUID, of which pseudo-probes are just the first consumer; not `DW_AT_LLVM_pseudo_probe_guid`, which would wrongly imply probe-only use.)
- **Emit:** ~3 lines in `DwarfUnit::applySubprogramAttributes` (near `addLinkageName:1445-1456`):
  `addUInt(SPDie, DW_AT_LLVM_guid, DW_FORM_data8, GUID);`, gated on pseudo-probes. For a definition DIE the `Function` is available (so `F.getGUID()` directly); for abstract/inlined subprograms use the `DISubprogram` stamped GUID (§4).
- **Read:** `DWARFDie::find(DW_AT_LLVM_guid)` + `low_pc`, in `llvm-profgen` / libhwtrace `getBinaryFunctionFromDwarf`.

**Properties:** robust; **GUID-scheme-agnostic** (offline reads whatever the compiler stamped — no reconstruction, no path contract, no header/`decl_file` hazard); unknown DWARF consumers ignore it. **Costs:** a vendor `DW_AT` + upstream review (gate emission behind probes to avoid DWARF bloat; precedent: `DW_AT_LLVM_stmt_sequence` `0x3e0c`). ~+10 bytes/subprogram in probe builds.

### Variant B (fallback): rederive the file-qualified name from DWARF and rehash

No new DWARF attribute. The offline tool reconstructs the hashed identifier from DWARF and computes the GUID itself:

- For each DWARF subprogram: read the **compile-unit file** (CU `DW_AT_name` [+ `DW_AT_comp_dir`]), the linkage name, and `low_pc`.
- Compute `GUID = MD5("<CU-file>;<linkage-name>")` and map it to `low_pc`.

**Requirement (critical):** the string hashed offline must byte-match what the *producer* hashed into the GUID. The stock metadata GUID uses `Module::getSourceFileName()` (`Globals.cpp:196`), which is the **raw command-line input path** and generally differs from the DWARF CU name (which is **absolutized + `remapDIPath`'d**, `CGDebugInfo.cpp:805-819`). Therefore Variant B requires **anchoring the probe GUID's file component on the DWARF CU file** so both sides agree — i.e. the file string fed to the GUID hash must be the CU `DIFile` string, on the producer (§5) *and* the matcher (§6) *and* here. Practically:
  - Use the **compile-unit file**, never the `DISubprogram` `decl_file` — a `static` in a header shares `decl_file` across TUs but differs by CU file (would collide).
  - Hazard: `-ffile-prefix-map` / relative-vs-absolute paths must produce identical strings on producer and consumer; add a prefix-map round-trip test.

**Properties:** no DWARF format change; works on any DWARF-bearing binary. **Costs:** the byte-identical path-reproduction contract; **not GUID-scheme-agnostic** — if the GUID derivation ever changes (e.g. content hash), Variant B breaks and cannot be reconstructed. It also forces the whole pipeline's GUID to be CU-file-anchored rather than free-form.

### Choosing

| | Variant A (vendor `DW_AT`) | Variant B (rederive + rehash) |
|---|---|---|
| DWARF format change | new vendor attribute + review | none |
| Offline reconstruction | none — read GUID directly | reconstruct CU-file + rehash |
| Path-normalization contract | none | required (byte-identical) |
| Survives GUID derivation change | yes | no |
| Constrains GUID to be CU-file-anchored | no (any derivation) | yes |
| DWARF size | +~10 B/subprogram (probe builds) | none |

**Recommendation:** ship Variant A. It matches the core principle (read, don't recompute) and future-proofs the derivation. Keep Variant B as the fallback if the vendor attribute is rejected upstream — in which case the design additionally requires anchoring the GUID's file component on the DWARF CU file so producer/matcher/offline all agree.

*(A third option, storing the CU-file path in `.pseudo_probe_desc` and joining `(path, name)→low_pc`, was considered ("D1"); it is strictly heavier than A for Apple where DWARF is guaranteed, and shares Variant B's path-contract, so it is not carried forward except as an interim before A lands.)*

## 10. dsymutil

The probe/desc sections are copied **verbatim** into the dSYM (`PseudoProbeLinker.cpp:156-181` on branch `dsymutil-collect-probes`; sections `__probes` / `__probe_descs`, matching what libhwtrace reads). Variant A adds the GUID to DWARF, which dsymutil already relocates/copies as normal debug info. Variant B needs nothing new from dsymutil. If the desc format is ever extended, add a **version marker** so mixed old/new layouts are not silently concatenated. (This branch must be merged with `origin/main`, which has the metadata-GUID infra but not the collection work.)

## 11. Phasing

- **P0 — base + merge.** Build on `origin/main` (has `39dcb0ff`); merge the `dsymutil-collect-probes` work.
- **P1 — uniqueness + matching.** Wire `AssignGUIDPass` onto the probe path; producer probe-intrinsic + descriptor and the use-time matcher use `F.getGUID()`; add the profile flag; `llvm-profgen` sets it; text `name@guid`. *(Inline tree + offline still recompute — keep name-consistent or gated until P2/P3.)*
- **P2 — `DISubprogram` GUID field.** Stamp it; inline-tree probe emission and stale-match inlined-frame anchors read it. Closes inline-context consistency and preserves stale matching.
- **P3 — offline binding.** Variant A (DWARF attribute) or Variant B (rederive), per §9. Offline tools bind `GUID → low_pc`.

## 12. Residual limitations

- **Same source path compiled twice with different `-D`** collides (both hash to the same `file;name`). Shared with `-funique-internal-linkage-names` (it also hashes only the path) — no regression. Fixable later by evolving the GUID derivation (content/build hash) **without touching consumers** under Variant A.
- **Variant B** additionally inherits path-normalization fragility (§9).

## 13. Effort & upstream

- Aligned with the accepted stable-GUID RFC ("simplify PGO"); the matcher change is flag-gated so existing sample PGO is untouched.
- Biggest external surface: the `DISubprogram` GUID field (P2, debug-info reviewers) and, for Variant A, the vendor `DW_AT` (small code, gating-review). Variant B trades those for a path-reproduction contract.
- Overall: Medium–High, landable in phases.

## Appendix — verified references (as of this checkout)

- Metadata GUID: `GlobalValue.h:610,617,642,650`; `Globals.cpp:85-110`; `getGlobalIdentifier` `Globals.cpp:170-197`; `AssignGUIDPass` `Utils/AssignGUID.cpp`.
- Producer: `SampleProfileProbe.cpp:349-353`; `MDBuilder.cpp:351-359`; `PseudoProbePrinter.cpp:49-56`; desc lowering `TargetLoweringObjectFile.cpp:195-229`; `MCPseudoProbeFuncDesc` `MCPseudoProbe.h:87-97`; probe section `MCPseudoProbe.cpp:88-90`.
- Matcher: `SampleProfReader.h:519-545,961-965`; `SampleProfile.cpp:363/375/822/951/1039/2106/2187-2203/2285`.
- Stale matcher: `SampleProfileMatcher.cpp:86-93,118,134,147-149,219-221`.
- Profile format: `SampleProf.h` `SecProfSummaryFlags` (bit `1<<3` free), statics `:1323+`; `FunctionId.h:63-66,88-91`; text writer `SampleProfWriter.cpp:584`; `llvm-profdata.cpp:932-944`.
- DWARF: `Dwarf.def` LLVM block `0x3e00-0x3e14`; emit `DwarfUnit.cpp:1445-1456`; `Dwarf.cpp:72`.
- dsymutil (other branch): `PseudoProbeLinker.cpp:156-181`.
