// Pre-load all mdx files as raw strings using Vite's import.meta.glob
// This runs at build time — no runtime fetch needed

const allFiles = import.meta.glob('../content/**/*.mdx', {
  query: '?raw',
  import: 'default',
  eager: false,
});

/**
 * Load a lesson's raw MDX content by its file path.
 * @param {string} filePath - e.g. "linux/navigation.mdx" or "Pre Security/Linux Fundamentals/Linux Fundamentals 1.mdx"
 * @returns {Promise<string>} raw MDX text
 */
export async function loadLesson(filePath) {
  // Normalize: build the glob key
  const key = `../content/${filePath}`;

  const loader = allFiles[key];
  if (loader) {
    return await loader();
  }

  // Try case-insensitive fallback
  const lowerKey = key.toLowerCase();
  const match = Object.keys(allFiles).find(k => k.toLowerCase() === lowerKey);
  if (match) {
    return await allFiles[match]();
  }

  return null;
}

// Export all available paths for debugging
export const availablePaths = Object.keys(allFiles).map(k =>
  k.replace('../content/', '')
);
