# HS Offline Stat Forge v2.5.0 — Additive All Skills

## Changed

- `All Skills` is now `All Skills Bonus (+N)`: it hooks the finished
  `gml_Script_StatAllSkills` result array (the same additive result hook used
  by Skill Haste and Faster Cast Rate) and adds N to element zero. Gear
  "+X All Skills", elemental skill flats and buffs keep stacking, so one point
  in every skill plus +19 shows 20, and a +2 All Skills item makes it 22.
- The old absolute behaviour stays available as `All Skills (Set Exact)`,
  which still replaces the function entry with a constant.
- The two modes patch the same function, so enabling one while the other is
  active is refused with a log message instead of installing a dead hook.
- Existing `hs_statforge_stats.json` files migrate automatically: the
  `all_skills` resolver is replaced and its default value becomes `19`.

## Why

- `ReturnTalentLevel` reaches the bonus through
  `ReturnSpecificStat -> StatAllSkills`, whose only caller is
  `ReturnSpecificStat`; the function body has no level cap constant, so the
  additive route produces levels above 20.
- The entry proxy skipped the native body entirely, which is why item bonuses
  never stacked in earlier versions.

## Verification

- Static: `StatAllSkills` ends in `MOV RAX,R14 + MOVAPS XMM6,[RSP+disp32]`,
  an already verified 11-byte epilogue; the resolver finds exactly one site.
- Live counter verification (native value, `+N`, real game calls in the
  panel and `hs_statforge.log`) is still required before calling it working
  on a given build.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.4.3 — Total Damage Resolver Fix

## Fixed

- Total Damage now hooks the real `CalculateEndDamage` result epilogue at
  `RVA 0x3A5425` on Steam 7.0.5.0. The previous resolver crossed into an
  anonymous helper and selected its always-zero result at `RVA 0x3A5714`.
- The resolver recognizes the large-frame
  `MOV RAX,[RBP+disp32] + LEA R11,[RSP+disp32]` epilogue shape, patches only
  the complete seven-byte result load, and rejects modified adjacent context.
- Added a regression test containing both the real epilogue and the misleading
  helper, plus native x64 execution coverage for the new hook shape.

## Verification

- The running 7.0.5.0 executable resolves to `0x3A5425` with original bytes
  `48 8B 85 00 0E 00 00`; all nine exact result resolvers pass read-only checks.
- Native execution verifies `10 × 1.5 = 15` and safe stack restoration for all
  five supported epilogue layouts.
- Live combat produced non-zero results at the corrected `0x3A5425` site,
  including `4712.48 × 5.85 = 27568`, `4743.68 × 11 = 52180.5`, and
  `4634.68 × 5.78 = 26788.5`. Every disable restored the native epilogue, and
  the final Restore All completed successfully.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.4.2 — Safe Monster Density

## Fixed

- Fixed the freeze/crash that could occur when 5x Monster Density exhausted
  Hero Siege's fixed protected-variable pool.
- Density now measures the live pool and safely stops extra creators before
  the game reaches its hard limit.
- Added a separate burst limiter for game builds where the pool layout cannot
  be verified safely.
- The panel now displays pool use and how many extra creators were safely
  skipped.

## Live verification

- Tested at 5x density across three consecutive combat-map transitions.
- Observed 468 native creator routes and 1,872 extra creators.
- Final protected-pool use was 179,770 / 262,144; Hero Siege remained open and
  responsive, the runtime unloaded cleanly, and Windows recorded no new crash.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.4.1 — Fast Density Startup

## Improved

- Monster Density now enables in about 0.5 seconds on the verified Hero Siege
  7.0.5.0 build instead of repeatedly scanning the complete GameMaker heap.
- The fast route is accepted only after the full executable SHA-256 matches.
- New or unknown game builds still fall back to the safe adaptive resolver.
- Disabling density was measured at about 0.1 seconds and still removes the
  hooks and unloads the embedded runtime completely.

## Verification

- Live test: enable completed in 0.515 seconds with all seven enemy creator
  routes validated.
- Disable completed in 0.108 seconds; the density DLL was no longer loaded.
- Hero Siege remained open and responsive after the lifecycle test.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.4.0 — Standalone Monster Density

## Added

- Monster Density from 1x to 5x in 0.5x steps.
- The required native runtime is embedded inside `HSStatForge.exe`.
- No ForgePact, Aurie, YYToolkit or separate DLL installation is required.

## Fixed

- GameMaker object references are now decoded through the game's own runtime
  converter, so density targets the correct enemy-creator objects.
- Every extra creator result is released correctly. This fixes the crash that
  could occur after moving to a second map with high density enabled.
- Density hooks unload automatically when disabled, restored, the panel closes,
  or the panel heartbeat is lost.

## Live verification

- Tested with Hero Siege 7.0.5.0 at 5x density.
- Multiple consecutive map transitions completed without a crash.
- Final test observed 1,206 native creators and 4,824 extra creators.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.3.0 — Extended Stats

## Added

- Total Damage Bonus
- Attack Speed Bonus
- Faster Cast Rate Bonus
- Skill Haste Bonus (cooldown recovery)
- Defense Bonus
- Critical Strike Chance Bonus
- Critical Strike Damage Bonus
- Spell Critical Chance Bonus
- Spell Critical Damage Bonus

Magic Find, Movement Speed, EXP Multiplier and All Skills remain available.
Percentage controls now mean exactly `+N%`, so `+100%` doubles the game's
native value. Faster Cast Rate and Skill Haste add points directly.

## Safety and diagnostics

- Added exact 7/8/11-byte YYC result-epilogue validation for Steam 7.0.5.0.
- Corrected the eight-byte stack displacement introduced by a CALL-based hook
  before replaying RSP-relative epilogue instructions.
- Attack Speed now treats the aggregate result as a scalar `VALUE_REAL`.
- A closed game now clears stale runtime state once instead of flooding the log.
- Added executable native tests for R14, R15, RSP and R11 epilogue layouts.

## Live verification

- Faster Cast Rate: `33 + 365 = 398`.
- Defense: `1464 × 5.5 = 8052`.
- Critical Chance: `25 × 4.22 = 105.5`.
- Critical Damage: `80.9 × 11 = 889.9`.
- Spell Critical Chance: `34 × 3.35 = 113.9`.
- Spell Critical Damage: `62 × 5.78 = 358.36`.
- Skill Haste: `12 + 100 = 112` over 631 live calls.
- Total Damage hook installation/restoration was observed, but the sampled
  calls returned zero; the resolver was corrected in v2.4.3 before claiming a
  non-zero combat result.
- Attack Speed: live native `23.1 × 4 = 92.4` over 48 calls. The earlier
  MainHand/OffHand array route was removed because those are detail queries.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.2.3 — Real Result Hooks

## Fixed

- Removed the ineffective protected-table route used by the unpublished
  v2.2.2 test build.
- Magic Find now scales `StatMagicFind` array element zero.
- Movement Speed now scales `StatMovementSpeed` array element zero.
- EXP now scales the completed `EnemyCalculateExperience` return value instead
  of changing an internal constant that remained `1.0` in gameplay.
- Added anti-compounding handling for GameMaker arrays reused between calls.
- Added live native/scaled values and game-call counters to the panel.
- Added persistent `hs_statforge.log` diagnostics beside the executable.

## Verification

- Steam Hero Siege 7.0.5.0: Movement Speed returned `77 × 2 = 154` over 42
  real game calls, then its native epilogue was restored byte-for-byte.
- Magic Find and EXP hook installation/restoration passed. Their gameplay
  calls are now visible in the panel and log for loot/kill verification.

Offline/single-player only. Launch Hero Siege without EAC.

---

# HS Offline Stat Forge v2.2.1 — Adaptive Module Resolver

## Fixed

- Added layered main-module discovery: Toolhelp, Pymem module APIs and native
  64-bit PEB image-base fallback.
- Attach now validates the in-memory MZ/PE image before reporting success.
- EAC-protected or unreadable processes receive a direct launch/yetki message.
- Removed the single-build `Hero_Siege.exe` SHA-256 allow-list that rejected
  compatible Steam and non-Steam Season 10 executables.
- Magic Find, Movement Speed and All Skills now resolve by exact GameMaker
  function name and validate the native YYC entry structure before patching.
- EXP Multiplier now resolves by a unique instruction context without requiring
  a whole-file fingerprint.
- Existing local v2 configuration files migrate automatically to the adaptive
  v3 resolver definitions.
- Restore operations verify original bytes before proxy memory is released.
- Non-finite stat values are rejected.

## Verification

- Read-only resolver tests pass against Hero Siege 7.0.0 (`ba72b95a...`).
- Read-only resolver tests pass against Steam Hero Siege 7.0.2 (`0766aa8b...`).
- Corrupted function entries are rejected without process writes.
- A forced test with Toolhelp and Pymem module discovery disabled resolves the
  executable base, image size and path through the PEB alone.

Offline/single-player only. Launch Hero Siege without EAC.
