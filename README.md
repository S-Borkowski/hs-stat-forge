HS Offline Stat Forge v2.4.2
============================

Adaptive Season 10 runtime stat editor for Hero Siege offline/single-player play.

Boosts
------
- Magic Find Multiplier (scales the native final value)
- Movement Speed Multiplier (scales the native final value)
- All Skills
- EXP Multiplier (multiplies the game's final experience reward)
- Total Damage Bonus (%)
- Attack Speed Bonus (%) from the live aggregate attack-timing value
- Faster Cast Rate Bonus (adds points instead of multiplying zero)
- Skill Haste Bonus (adds cooldown-recovery points to the native value)
- Defense Bonus (%)
- Critical Strike Chance and Damage Bonus (%)
- Spell Critical Chance and Damage Bonus (%)
- Monster Density Multiplier (1x to 5x in 0.5x steps)

Quick start
-----------
1. Launch Hero Siege without Easy Anti-Cheat and enter offline mode.
2. Run HSStatForge.exe and accept the administrator prompt.
3. Choose Attach / Select.
4. Set a value and enable the desired boost.
5. Use Restore All before leaving the game to return to native values.

Compatibility
-------------
- StatForge no longer requires one exact Hero_Siege.exe SHA-256 hash.
- Main-module discovery falls back from Toolhelp to Pymem and the native PEB.
- It locates named Season 10 functions at runtime and validates each target's
  native YYC entry layout before writing.
- Magic Find and Movement Speed hook the native Stat* result arrays and scale
  element zero, which is the value the game actually consumes.
- EXP scales the completed EnemyCalculateExperience return value.
- Percentage bonus controls use `native × (1 + bonus / 100)`, so +100% doubles
  the native value. Faster Cast Rate and Skill Haste add points directly.
- RSP-relative native epilogues are replayed with CALL-stack compensation.
- Attack Speed scales the scalar `StatAttackSpeed` result used by gameplay;
  the hand-specific detail arrays are intentionally not patched.
- The panel and hs_statforge.log show native value, scaled value and actual
  game-call counts, so a written patch is not mistaken for a working stat.
- Unsupported layouts are rejected without a write.
- Live apply/restore verification passed on Steam Hero Siege 7.0.5.0.
- Monster Density uses StatForge's own embedded native runtime. It does not
  require ForgePact, Aurie, YYToolkit, or a separately installed plugin.
- Density resolves the current GameMaker create functions and the complete
  Enemy_Creator object block at runtime. Ambiguous layouts are blocked safely.
- Hero Siege 7.0.5.0 uses an exact-file verified fast path, reducing the tested
  density startup from a long heap scan to about half a second. Unknown builds
  keep the safe adaptive resolver instead of trusting stale addresses.
- Density watches Hero Siege's protected-variable pool and stops creating
  extras before that fixed pool can be exhausted. A separate per-second cap
  also prevents one map load from producing an unsafe burst.
- The panel reports live pool use and the number of safely skipped creators.
- Every extra creator result is released through GameMaker's own FREE_RValue
  helper, preventing reference buildup during repeated map transitions.
- Closing StatForge, Restore All, or a lost heartbeat removes both density
  hooks and unloads the embedded DLL from the game process.

Important
---------
- Offline/single-player use only.
- Do not use with multiplayer, online characters, leaderboards, trading, or EAC.
- Hero_Siege.exe on disk is never modified.
- Keep hs_statforge_stats.json beside HSStatForge.exe.

Developer research
------------------
- See STATFORGE_S10_REAL_STAT_HOOK_NOTES.md before adding another stat.
