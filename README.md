# HS Offline Stat Forge

Adaptive Season 10 runtime stat editor for Hero Siege offline/single-player characters.

> Current release: **v2.2.0 — Adaptive Build Resolver**

## Season 10 boosts

- Magic Find
- Movement Speed
- All Skills
- EXP Multiplier

The verified Season 10 routes override native runtime results in memory. The game executable on disk is never modified. Every active change can be reverted with **Restore All** and the application also restores active changes when it closes normally.

Version 2.2.0 no longer allow-lists one exact `Hero_Siege.exe` hash. It resolves each named GameMaker function at runtime and validates the target's native YYC instruction layout before writing. Compatible builds can move code without breaking StatForge; genuinely changed layouts are still rejected safely.

## Quick start

1. Download `HS-Offline-Stat-Forge-v2.2.0.zip` from the latest release.
2. Extract the full archive to a normal folder.
3. Start Hero Siege with **Launch Without EAC**, then enter offline/single-player mode.
4. Run `HSStatForge.exe` and accept the administrator prompt.
5. Choose **Attach / Select**, set a value and enable the desired boost.
6. Use **Restore All** before leaving the game if you want to return to native values immediately.

Keep `hs_statforge_stats.json` next to the executable. Value choices are saved locally in this file.

## Compatibility and safety

- Designed only for Hero Siege Season 10 offline/single-player use.
- Do not use it with multiplayer, online characters, leaderboards, trading or anti-cheat protected modes.
- Magic Find, Movement Speed and All Skills resolve by exact function name plus validated YYC entry structure.
- EXP Multiplier resolves by a unique instruction context and uses private runtime proxy memory.
- Read-only compatibility tests pass against Hero Siege 7.0.0 and Steam 7.0.2.
- A changed target layout is rejected instead of receiving an unsafe patch.
- Antivirus products may flag unsigned memory-editing tools heuristically. Verify the downloaded files against `SHA256SUMS.txt`.

## Source

The Python sources used for the packaged executable are included in this repository.
