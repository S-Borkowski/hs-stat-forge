HS Offline Stat Forge v2.3.0
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

Important
---------
- Offline/single-player use only.
- Do not use with multiplayer, online characters, leaderboards, trading, or EAC.
- Hero_Siege.exe on disk is never modified.
- Keep hs_statforge_stats.json beside HSStatForge.exe.

Developer research
------------------
- See STATFORGE_S10_REAL_STAT_HOOK_NOTES.md before adding another stat.
