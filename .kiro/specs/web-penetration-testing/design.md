# Design Document

## Feature: Web Penetration Testing

---

## Overview

This feature adds a single new entry to the `learningPaths` array in `study-hub-react/src/data/learning-paths-data.js`. No new components, routes, or backend changes are required — the existing `LearningTracks.jsx`, `PlaylistWizard.jsx`, and `TrackDetail.jsx` all dynamically render from that array.

The new track teaches web application penetration testing: OWASP Top 10, Burp Suite, SQL injection, XSS, IDOR, and related techniques. It sits in the intermediate tier, after `soc-analyst-1` and before the advanced section, and participates in the PlaylistWizard for future playlist assignment. Content modules will be populated later via the wizard.

---

## Architecture

The platform follows a data-driven rendering pattern for learning tracks:

```
learning-paths-data.js  (single source of truth)
        │
        ├── LearningTracks.jsx   — renders a card grid, filters by level/search
        ├── PlaylistWizard.jsx   — iterates non-locked tracks for playlist assignment
        └── TrackDetail.jsx      — renders full track detail by id param
```

Adding a new track requires only a new object in the `learningPaths` array. All three consumers read the array at runtime; no imports, routes, or component logic need to change.

---

## Components and Interfaces

No new components are introduced. The change touches one file:

**`study-hub-react/src/data/learning-paths-data.js`**

The `Bug` icon from `lucide-react` is already imported in this file and will be used as the track icon — semantically appropriate for a bug-hunting / vulnerability-focused track.

The new entry must conform to the Learning_Path schema consumed by all three pages:

| Field | Type | Notes |
|---|---|---|
| `id` | `string` | Unique kebab-case identifier |
| `title` | `string` | English title |
| `titleAr` | `string` | Arabic title |
| `description` | `string` | English description |
| `descriptionAr` | `string` | Arabic description |
| `level` | `'beginner' \| 'intermediate' \| 'advanced' \| 'expert'` | Controls badge and filter |
| `duration` | `string` | Display string e.g. `'40 Hours'` |
| `modules` | `number` | Module count (0 for placeholder) |
| `students` | `number` | Student count seed |
| `icon` | Lucide React component | Used as card watermark and wizard icon |
| `skills` | `string[]` | Shown as tags on card and detail page |
| `certGoals` | `string[]` | Shown in Certifications tab |
| `isLocked` | `boolean?` | Omitted or `false` = accessible |
| `contentModules` | `object[]` | Empty array = "Content Coming Soon" in TrackDetail |
| `youtubePlaylists` | `object[]` | Empty array = wizard-assigned later |

---

## Data Models

The new object to be inserted into `learningPaths` after `soc-analyst-1` and before the advanced section:

```js
{
  id: 'web-penetration-testing',
  title: 'Web Penetration Testing',
  titleAr: 'اختبار اختراق تطبيقات الويب',
  description: 'Master web application hacking from the ground up. OWASP Top 10, Burp Suite, SQL injection, XSS, IDOR, and beyond.',
  descriptionAr: 'أتقن اختبار اختراق تطبيقات الويب من الصفر. OWASP Top 10 وBurp Suite وحقن SQL وXSS وIDOR والمزيد.',
  level: 'intermediate',
  duration: '40 Hours',
  modules: 0,
  students: 0,
  icon: Bug,
  skills: ['OWASP Top 10', 'Burp Suite', 'SQL Injection', 'XSS', 'IDOR'],
  certGoals: ['eWPT', 'BSCP', 'OSWA'],
  contentModules: [],
  youtubePlaylists: [],
},
```

**Placement rationale**: The intermediate section currently ends with `soc-analyst-1`. Web penetration testing is a natural next step after the Jr Penetration Tester track (which covers general pentesting) and the SOC Analyst track (which covers defensive skills). Placing it last in the intermediate section, immediately before the advanced tracks, reflects its position as a specialization that bridges intermediate and advanced skill levels.

**Icon rationale**: `Bug` is already imported in `learning-paths-data.js` and is the most semantically direct icon for a web vulnerability / bug-hunting track. Using an already-imported icon avoids any import changes.

**`modules: 0`**: `TrackDetail.jsx` computes `totalLessons` from `contentModules` directly, so the `modules` field is only used for the display stat on the card. Setting it to `0` is honest and consistent with the empty `contentModules` array.

**`students: 0`**: Initialized to zero since no learners have enrolled yet. The card renders `0` via `toLocaleString()` without issue.

**`certGoals`**: eWPT (eLearnSecurity Web Penetration Tester), BSCP (Burp Suite Certified Practitioner), and OSWA (Offensive Security Web Assessor) are the three most recognized web-specific penetration testing certifications, directly aligned with the track's skill set.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Level filter includes all matching tracks

*For any* track in `learningPaths` with `level === 'intermediate'`, when the Learning Tracks page filters by the "Intermediate" level, that track must appear in the filtered results.

**Validates: Requirements 3.2**

---

### Property 2: Search matches title, description, and skills

*For any* track in `learningPaths`, when a user searches for a substring that appears in the track's `title`, `description`, or `skills` array, that track must appear in the filtered results.

**Validates: Requirements 3.3**

---

### Property 3: Intermediate tracks render the intermediate badge

*For any* track in `learningPaths` with `level === 'intermediate'`, the rendered card must display the intermediate level badge consistent with other intermediate tracks.

**Validates: Requirements 3.5**

---

### Property 4: Arabic rendering uses titleAr and descriptionAr

*For any* track in `learningPaths` that has `titleAr` and `descriptionAr` fields, when the platform language is set to Arabic, the rendered output (both on the Learning Tracks page and in the PlaylistWizard) must contain `titleAr` and `descriptionAr` rather than the English fields.

**Validates: Requirements 2.3, 2.4**

---

### Property 5: Locked tracks are excluded from PlaylistWizard

*For any* track in `learningPaths` where `isLocked === true`, the PlaylistWizard must not include that track as a wizard step.

**Validates: Requirements 4.5**

---

### Property 6: PlaylistWizard persists selections to localStorage

*For any* track id and any set of playlist ids selected in the PlaylistWizard, after the selection is made, `localStorage.getItem('track_playlists')` must contain those playlist ids under the track's id key.

**Validates: Requirements 4.3**

---

### Property 7: PlaylistWizard step displays required track metadata

*For any* non-locked track in `learningPaths`, the corresponding PlaylistWizard step must display the track's title (or `titleAr` when language is Arabic), level badge, duration, and description.

**Validates: Requirements 4.2**

---

## Error Handling

Since this change is purely additive data, the error surface is minimal:

- **Missing icon import**: `Bug` is already imported — no risk. If a future track uses an unimported icon, the component will throw a render error. Mitigation: always verify icon imports before adding a track.
- **Malformed object shape**: If a required field is missing (e.g., `skills` is undefined), `LearningTracks.jsx` guards with `path.skills?.slice(0, 4)` and `TrackDetail.jsx` uses `(track.certGoals || [])`, so most missing fields degrade gracefully rather than crashing.
- **Empty contentModules**: `TrackDetail.jsx` explicitly handles `contentModules.length === 0` by rendering a "Content Coming Soon" placeholder — this is the intended behavior for this track.
- **Empty youtubePlaylists**: `TrackDetail.jsx` handles an empty playlist list by rendering a "No playlists selected yet" state with a link to the wizard — also the intended behavior.

---

## Testing Strategy

This feature is a data-only change, so the testing strategy is lightweight but still covers the key correctness properties.

### Unit Tests

Focus on the specific shape and values of the new track object:

- **Track schema test**: Import `learningPaths`, find the entry with `id: 'web-penetration-testing'`, and assert all required fields are present with correct types and values (id, title, titleAr, description, descriptionAr, level, duration, modules, students, icon, skills, certGoals, contentModules, youtubePlaylists).
- **Skills containment test**: Assert that the skills array contains all five required values: `['OWASP Top 10', 'Burp Suite', 'SQL Injection', 'XSS', 'IDOR']`.
- **certGoals test**: Assert that certGoals is non-empty and contains `'eWPT'`, `'BSCP'`, and `'OSWA'`.
- **Empty arrays test**: Assert `contentModules.length === 0` and `youtubePlaylists.length === 0`.
- **Array ordering test**: Assert the web-penetration-testing track appears after `soc-analyst-1` and before the first advanced track in the array.
- **Navigation test**: Assert clicking the card navigates to `/track/web-penetration-testing`.
- **Wizard inclusion test**: Assert the web-penetration-testing track appears in the wizard's track list (i.e., it is not locked).
- **Wizard summary test**: Assert the web-penetration-testing track appears in the wizard's summary step.

### Property-Based Tests

Each property test should run a minimum of 100 iterations. Use a property-based testing library appropriate for the project's stack (e.g., `fast-check` for JavaScript/TypeScript).

Tag format for each test: `Feature: web-penetration-testing, Property {N}: {property_text}`

- **Property 1 test** — `Feature: web-penetration-testing, Property 1: Level filter includes all matching tracks`
  Generate random subsets of `learningPaths` entries with `level === 'intermediate'`. For each, assert the filter function returns them when `selectedLevel === 'intermediate'`.

- **Property 2 test** — `Feature: web-penetration-testing, Property 2: Search matches title, description, and skills`
  For each track in `learningPaths`, generate random substrings of its `title`, `description`, and elements of its `skills` array. Assert the filter function returns the track for each substring.

- **Property 3 test** — `Feature: web-penetration-testing, Property 3: Intermediate tracks render the intermediate badge`
  For any track object with `level === 'intermediate'`, render the badge logic and assert the output text matches the intermediate badge label.

- **Property 4 test** — `Feature: web-penetration-testing, Property 4: Arabic rendering uses titleAr and descriptionAr`
  For any track object with both `titleAr` and `descriptionAr`, render the component with `language='ar'` and assert the Arabic strings appear in the output (and the English strings do not replace them).

- **Property 5 test** — `Feature: web-penetration-testing, Property 5: Locked tracks are excluded from PlaylistWizard`
  Generate random arrays of track objects where some have `isLocked: true`. Assert the wizard's filtered track list contains none of the locked tracks.

- **Property 6 test** — `Feature: web-penetration-testing, Property 6: PlaylistWizard persists selections to localStorage`
  For any track id and any array of playlist ids, simulate a selection toggle and assert `localStorage` contains the expected ids under `track_playlists[trackId]`.

- **Property 7 test** — `Feature: web-penetration-testing, Property 7: PlaylistWizard step displays required track metadata`
  For any non-locked track object, render the `TrackStep` component and assert the rendered output contains the track's title, level, duration, and description.
