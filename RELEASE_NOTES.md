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
- Total Damage was verified in live combat and restores safely.
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
