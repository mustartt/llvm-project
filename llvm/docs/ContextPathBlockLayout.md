# Context-Path-Sensitive Basic Block Layout

**Status:** design note + experimental prototype (gated behind
`-mbp-path-profile-file`, default off).

This note describes an approach to basic-block layout that consumes
*context-path* profile information — how execution actually reached a block —
rather than only order-0 per-edge probabilities, and documents an experimental
prototype already in tree.

> Microarchitectural specifics of the target front end that make this profitable
> (trace/fetch caches, stable-branch fetch accelerators, instruction aligners,
> misprediction costs) are target-dependent and live in the relevant CPU tuning
> guides. They are intentionally **not** reproduced here; this note stays within
> LLVM-observable engineering detail.

---

## 1. Motivation

LLVM block layout has two layers:

- **`MachineBlockPlacement`** (`llvm/lib/CodeGen/MachineBlockPlacement.cpp`) — a
  probability-greedy, structure-preserving chain builder (the default).
- **Ext-TSP** (`llvm/lib/Transforms/Utils/CodeLayout.cpp`, enabled by
  `-enable-ext-tsp-block-placement`, off by default) — an optional post-pass
  implementing Newell & Pupyrev, *Improved Basic Block Reordering*
  (arXiv:1809.04676), which optimizes an edge-weighted proxy for I-cache/fetch
  locality.

Both consume only **order-0** profile information: per-edge branch probabilities
(`MachineBranchProbabilityInfo`) and block frequencies
(`MachineBlockFrequencyInfo`). Two observations motivate going further on
front-end-bound targets:

1. **Paths carry more than edges.** With a full branch trace (LBR/SPE-derived)
   the actual execution *paths* are known, not just per-edge aggregates. Two CFGs
   with identical edge weights can have very different path behavior, and a
   fetch-bound front end (branch predictors, any trace/fetch caches) is path- and
   branch-stability-sensitive in ways an edge weight cannot express.
2. **Pseudo-probes make it deliverable.** Pseudo-probes give an
   optimization-stable correlation from profile samples to blocks that survives
   to MIR, so path information can reach codegen without the staleness that
   affects source-line correlation.

---

## 2. Where path information is lost today

The channel `MachineBlockPlacement` consumes is per-edge `BranchProbability` on
MBB successors, populated two ways:

1. **IR path:** `SampleProfileLoader` (IR) → `branch_weights` metadata →
   `SelectionDAGBuilder` sets MBB successor probabilities at ISel →
   `MachineBranchProbabilityInfo` reads them back.
2. **MIR refresh path:** `TargetPassConfig::addBlockPlacement()`
   (`TargetPassConfig.cpp:1571`) inserts `createMIRProfileLoaderPass(...)`
   **immediately before** `MachineBlockPlacementID` (`:1577`→`:1581`). That pass
   (`MIRSampleProfile.cpp`) re-reads the probe-based sample profile at MIR and
   rewrites the channel via `setBranchProbs` → `BB->setSuccProbability` (`:255`),
   correlating through pseudo-probes that survive to MIR (`llvm.pseudoprobe` →
   `ISD::PSEUDO_PROBE` at `SelectionDAGBuilder.cpp:7812` → `PSEUDO_PROBE` machine
   instr at `SelectionDAGISel.cpp:3386`). FS discriminators
   (`MIRAddFSDiscriminators`) disambiguate edges sharing one probe/line.

Two gaps follow:

1. **The sample-profile format has no transition/path counts.**
   `FunctionSamples` = `BodySamples` (per-probe *block* counts + call targets) +
   `CallsiteSamples` (the *inline* context stack) (`SampleProf.h`). Edge weights
   are *inferred* from block counts; "context" here means calling/inline context,
   not intra-procedural block path. k-th-order transition counts are absent.
2. **The placement channel is order-0 by construction.** One `BranchProbability`
   per successor is memoryless; it cannot represent `P(next | arrival-context)`.

**The correlation backbone we need already exists** (probes at MIR + a loader
slot right before placement); only the representation and a richer query are
missing.

---

## 3. Recommended data path

Extend the existing `MIRProfileLoader` slot rather than rebuilding correlation:

- **Generation:** extend `llvm-profgen` to emit, from the branch trace, **k-gram
  transition counts keyed by probe-ID sequences**
  (`(GUID,probe)…(GUID,probe) → succ-probe : count`), small k (≈2–4), pruned.
- **Representation:** a **new SampleProf section** (do not overload
  `BodySamples`).
- **Propagation:** a pass in the existing pre-placement slot (extend
  `MIRProfileLoader` or a sibling reusing its probe correlation /
  `EquivalenceClass`) loads the section and exposes a `MachinePathProfile`
  analysis answering `count(context → succ)` per MBB, which
  `MachineBlockPlacement` / Ext-TSP query.
- **Complementary — structural baking via tail duplication:** where a
  context-predictable join can be cheaply duplicated, duplicating it upstream
  gives each copy a single dominant context, so the existing order-0
  `setSuccProbability` channel already encodes the path — no new channel needed
  for those cases. `MachineBlockPlacement` already performs profile-gated tail
  duplication (`isProfitableToTailDup`); the extension is to re-gate it on exact
  path benefit.

An **analysis MBP queries** (rather than precomputed probabilities) is required
because MBP tail-duplicates *during* placement, so context-aware decisions must
be made with the counts live.

Alternatives considered and rejected: IR metadata (does not survive to MIR; IR
blocks ≠ MBBs after ISel/if-conv/tail-dup); enriching only `setSuccProbability`
(order-0 by definition); precomputing the full layout at IR (IR↔MBB mismatch;
MBP is the layout authority); re-reading the profile fresh inside MBP (duplicates
existing correlation logic).

---

## 4. Experimental prototype (in tree)

A first, self-contained prototype of the **consumption** side lives in
`MachineBlockPlacement.cpp`, gated by `-mbp-path-profile-file=<file>` (default
off → behavior unchanged).

**What it does:**
- `initPathProfile()` correlates each MBB to a block probe `(GUID, Index)` by
  scanning `PSEUDO_PROBE` machine instrs (present at placement time), and loads a
  text carrier of `context → successor : count` entries. The text file is a
  **stand-in** for the future SampleProf section of §3.
- In `selectBestSuccessor`, the **arrival context is the already-placed chain
  prefix ending at the current block** — available for free, since MBP passes the
  chain in. `selectContextualSuccessor()` looks up the highest-count successor for
  that context, backing off from the longest available context (TAGE-style), and
  overrides the order-0 choice **only** when the chosen successor is viable here.

**Carrier format** (one entry per line; `#` comments):

```
<ctxProbe1> <ctxProbe2> ... <ctxProbeK> -> <succProbe> : <count>
```

each probe is `GUID:Index`; the last context probe is the block's own probe.

**Test:** `llvm/test/CodeGen/AArch64/machine-block-placement-path-profile.mir`
— a diamond whose branch has two equally-likely successors (order-0 tie), where
the path profile flips which successor becomes the fall-through. Verified: the
opposite target agrees with baseline, len-1 context backs off correctly, and a
non-matching context cleanly falls back to order-0.

**Limitations / scope of the prototype:**
- Consumption only. Generation (`llvm-profgen` + SampleProf section) and wiring
  through `MIRProfileLoader` are follow-ons; the text file stands in for both.
- Reorders among existing successors only; it does not yet drive context-aware
  tail duplication (the natural next step, via `isProfitableToTailDup`).

---

## 5. Full algorithm (future direction)

The prototype is the thin end of a larger design that treats layout as covering
blocks with **stable hot path-bundles** rather than maximizing fall-throughs:

- Build a bounded-order (k≈2–4) **context tree** from the trace; classify each
  branch as **stable** (deterministic at order 0), **context-predictable**
  (deterministic only given arrival path), or **unpredictable** (high entropy —
  a hard cut point).
- Grow bundles as context-sensitive superblocks, cut at unpredictable branches;
  resolve context-predictable joins with **profitability-gated tail duplication**
  (benefit from exact path frequency minus code-size/footprint cost).
- Lift the result to a bundle graph and reuse the existing chain-merge/Ext-TSP
  machinery on it. Ext-TSP is recovered as the k=0, no-duplication special case.

The scoring function is a target front-end model (abstracted here); its details
belong in the target's tuning documentation.

### Target-independent layout notes

- **Alignment is a non-lever on targets with a hardware fetch aligner.** Such
  cores fetch at arbitrary alignment, so block/loop alignment NOPs cannot improve
  fetch bandwidth and only cost footprint. LLVM already reflects this: Apple
  AArch64 subtargets leave `PrefLoopAlignment = Align(1)`
  (`AArch64Subtarget.cpp`), so `MachineBlockPlacement::alignBlocks` is inert for
  them. Layout for such targets must not trade footprint for alignment.
- **Orient the hot path as the fall-through.** Where a front end's cold /
  post-eviction default for an untrained branch is "not taken / fall through,"
  making the dominant path the fall-through is correct across cold, evicted, and
  trained states — a robustness argument independent of steady-state weights.

---

## 6. Next steps

- Define the probe-keyed path-count SampleProf section and the
  `MachinePathProfile` MIR analysis (§3); pick the k bound and pruning policy.
- Teach `llvm-profgen` to emit the section from LBR/SPE traces.
- Extend the prototype from reorder-only to context-aware tail duplication.
- Decide IR-level vs. post-link application; the former enables co-optimization
  with inlining/unrolling but must survive late MIR passes.
