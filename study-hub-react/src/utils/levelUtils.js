/**
 * Level & Rank Utility Functions
 * ================================
 * Single source of truth for XP → Level → Rank calculations.
 * Must stay in sync with backend/gamification_engine.py
 *
 * Backend formula:  level = floor(0.1 * sqrt(total_xp))
 */

// ── Level calculation ────────────────────────────────────────────────────────

/**
 * Calculate the level from total XP.
 * Matches: gamification_engine.py :: calculate_level()
 * @param {number} xp
 * @returns {number} level (0-based)
 */
export const calculateLevel = (xp) => {
  if (!xp || xp <= 0) return 0;
  return Math.floor(0.1 * Math.sqrt(xp));
};

/**
 * Calculate the minimum XP required to reach a specific level.
 * Matches: gamification_engine.py :: calculate_xp_for_level()
 * @param {number} level
 * @returns {number} minimum XP
 */
export const xpForLevel = (level) => {
  if (level <= 0) return 0;
  return Math.ceil((level / 0.1) ** 2);
};

/**
 * Get detailed level progress info for a given XP value.
 * @param {number} totalXp
 * @returns {{ currentLevel: number, progressPercent: number, xpInLevel: number, xpNeeded: number, nextLevelXp: number }}
 */
export const getLevelProgress = (totalXp) => {
  const currentLevel = calculateLevel(totalXp);
  const currentLevelXp = xpForLevel(currentLevel);
  const nextLevelXp = xpForLevel(currentLevel + 1);

  const xpInLevel = totalXp - currentLevelXp;
  const xpNeeded = nextLevelXp - currentLevelXp;
  const progressPercent = xpNeeded > 0
    ? Math.min(100, Math.round((xpInLevel / xpNeeded) * 100))
    : 100;

  return {
    currentLevel,
    progressPercent,
    xpInLevel,
    xpNeeded: Math.max(0, xpNeeded - xpInLevel),
    currentLevelXp,
    nextLevelXp,
  };
};

// ── Rank titles ──────────────────────────────────────────────────────────────
// Ordered from highest to lowest, matching gamification_engine.py :: get_level_title()

export const RANK_TITLES = [
  { minLevel: 30, name: 'Cyber God',     nameAr: 'إله السايبر' },
  { minLevel: 25, name: 'Legend',        nameAr: 'أسطورة' },
  { minLevel: 20, name: 'Grandmaster',   nameAr: 'جراند ماستر' },
  { minLevel: 16, name: 'Master',        nameAr: 'ماستر' },
  { minLevel: 12, name: 'Elite Hacker',  nameAr: 'هاكر محترف' },
  { minLevel:  8, name: 'Cyber Warrior', nameAr: 'محارب سيبراني' },
  { minLevel:  5, name: 'Hacker',        nameAr: 'هاكر' },
  { minLevel:  3, name: 'Apprentice',    nameAr: 'متدرب' },
  { minLevel:  1, name: 'Script Kiddie', nameAr: 'سكريبت كيدي' },
  { minLevel:  0, name: 'Newbie',        nameAr: 'مبتدئ' },
];

/**
 * Get the rank title for a given level.
 * @param {number} level
 * @param {'en'|'ar'} [lang='en']
 * @returns {string}
 */
export const getRankTitle = (level, lang = 'en') => {
  const rank = RANK_TITLES.find((r) => level >= r.minLevel);
  if (!rank) return lang === 'ar' ? 'مبتدئ' : 'Newbie';
  return lang === 'ar' ? rank.nameAr : rank.name;
};

// ── LEVELS array (for backwards-compatibility with components that consume it) ─
// Represents each rank boundary as a level entry.

export const LEVELS = [...RANK_TITLES]
  .reverse()
  .map((r) => ({
    level:  r.minLevel,
    name:   r.name,
    nameAr: r.nameAr,
    minXP:  xpForLevel(r.minLevel),
  }));
