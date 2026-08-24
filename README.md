# HS Offline Stat Forge

Season 10 compatible runtime stat editor for Hero Siege offline/single-player characters.

## Season 10 boosts

- Magic Find
- Movement Speed
- All Skills
- EXP Multiplier

The verified Season 10 routes override native runtime results in memory. The game executable on disk is never modified. Every active change can be reverted with **Restore All** and the application also restores active changes when it closes normally.

## Quick start

1. Download `HS-Offline-Stat-Forge-v2.1.0.zip` from the latest release.
2. Extract the full archive to a normal folder.
3. Start Hero Siege in offline/single-player mode.
4. Run `HSStatForge.exe`.
5. Choose **Attach / Select**, set a value and enable the desired boost.
6. Use **Restore All** before leaving the game if you want to return to native values immediately.

Keep `hs_statforge_stats.json` next to the executable. Value choices are saved locally in this file.

## Compatibility and safety

- Designed only for Hero Siege Season 10 offline/single-player use.
- Do not use it with multiplayer, online characters, leaderboards, trading or anti-cheat protected modes.
- Runtime routes are verified against the supported Season 10 `Hero_Siege.exe` build. A changed game build is rejected instead of receiving an unsafe patch.
- Antivirus products may flag unsigned memory-editing tools heuristically. Verify the downloaded files against `SHA256SUMS.txt`.

## Source

The Python sources used for the packaged executable are included in this repository.
