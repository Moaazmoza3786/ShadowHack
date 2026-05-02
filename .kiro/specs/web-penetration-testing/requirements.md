# Requirements Document

## Introduction

This feature adds a new learning track called "Web Penetration Testing" to the BreachLabs/StudyHub cybersecurity learning platform. The track teaches web application hacking skills — OWASP Top 10, Burp Suite, SQL injection, XSS, IDOR, and more — and appears on the Learning Tracks page at the intermediate level, between the beginner tracks and the advanced tracks. It also participates in the PlaylistWizard so users can assign YouTube playlists to it. Content modules will be populated later via the wizard.

## Glossary

- **Platform**: The BreachLabs/StudyHub cybersecurity learning platform (React frontend + Python backend)
- **Learning_Tracks_Page**: The `/learning-tracks` route rendered by `LearningTracks.jsx`, which displays all learning paths from `learning-paths-data.js`
- **Learning_Path**: A structured entry in the `learningPaths` array in `learning-paths-data.js`, containing id, title, titleAr, description, descriptionAr, level, duration, modules, students, icon, skills, certGoals, contentModules, and youtubePlaylists fields
- **Track**: Synonym for Learning_Path used in UI context
- **PlaylistWizard**: The `/playlist-wizard` route that iterates over all non-locked tracks and lets users assign YouTube playlists to each
- **Web_Pentest_Track**: The new "Web Penetration Testing" Learning_Path being added
- **learning-paths-data.js**: The data file at `study-hub-react/src/data/learning-paths-data.js` that exports the `learningPaths` array
- **Bilingual_Support**: The platform's requirement to display content in both English and Arabic
- **OWASP_Top_10**: The Open Web Application Security Project's list of the ten most critical web application security risks

---

## Requirements

### Requirement 1: Add Web Penetration Testing Track to Learning Paths Data

**User Story:** As a platform administrator, I want the "Web Penetration Testing" track defined in `learning-paths-data.js`, so that it is available to all parts of the platform that consume the `learningPaths` array.

#### Acceptance Criteria

1. THE `learning-paths-data.js` SHALL contain a new Learning_Path entry with `id: 'web-penetration-testing'`.
2. THE Web_Pentest_Track SHALL have `level: 'intermediate'` so it appears in the intermediate tier alongside "Jr Penetration Tester" and "SOC Analyst Level 1".
3. THE Web_Pentest_Track SHALL use the `Bug` icon from `lucide-react`, which is already imported in `learning-paths-data.js`.
4. THE Web_Pentest_Track SHALL include a `skills` array containing at minimum: `['OWASP Top 10', 'Burp Suite', 'SQL Injection', 'XSS', 'IDOR']`.
5. THE Web_Pentest_Track SHALL include `certGoals` referencing at least one relevant web security certification (e.g., `['eWPT', 'BSCP', 'OSWA']`).
6. THE Web_Pentest_Track SHALL have `isLocked` omitted or set to `false` so it is accessible and not shown as "COMING SOON".
7. THE Web_Pentest_Track SHALL include an empty `contentModules` array as a placeholder for future content.
8. THE Web_Pentest_Track SHALL include an empty `youtubePlaylists` array as a placeholder for wizard-assigned playlists.

---

### Requirement 2: Bilingual Track Metadata

**User Story:** As an Arabic-speaking learner, I want the Web Penetration Testing track to display its title and description in Arabic, so that I can understand the track in my preferred language.

#### Acceptance Criteria

1. THE Web_Pentest_Track SHALL include a `titleAr` field with an Arabic translation of the track title.
2. THE Web_Pentest_Track SHALL include a `descriptionAr` field with an Arabic translation of the track description.
3. WHEN the platform language is set to Arabic, THE Learning_Tracks_Page SHALL display `titleAr` and `descriptionAr` for the Web_Pentest_Track.
4. WHEN the platform language is set to Arabic, THE PlaylistWizard SHALL display `titleAr` and `descriptionAr` for the Web_Pentest_Track in the track header.

---

### Requirement 3: Track Visibility on Learning Tracks Page

**User Story:** As a learner, I want to see the "Web Penetration Testing" track on the Learning Tracks page, so that I can discover and start the track.

#### Acceptance Criteria

1. WHEN a user navigates to the Learning Tracks page, THE Learning_Tracks_Page SHALL render a card for the Web_Pentest_Track.
2. WHEN a user filters by "Intermediate" level, THE Learning_Tracks_Page SHALL include the Web_Pentest_Track card in the filtered results.
3. WHEN a user searches for "web" or "burp" or "OWASP", THE Learning_Tracks_Page SHALL include the Web_Pentest_Track card in the search results.
4. WHEN a user clicks the Web_Pentest_Track card, THE Platform SHALL navigate to `/track/web-penetration-testing`.
5. THE Web_Pentest_Track card SHALL display the intermediate level badge consistent with other intermediate tracks.

---

### Requirement 4: Track Participation in PlaylistWizard

**User Story:** As a learner, I want the Web Penetration Testing track to appear in the PlaylistWizard, so that I can assign YouTube playlists to it for self-directed study.

#### Acceptance Criteria

1. WHEN the PlaylistWizard loads, THE PlaylistWizard SHALL include the Web_Pentest_Track as one of its steps.
2. WHILE iterating tracks in the PlaylistWizard, THE PlaylistWizard SHALL display the Web_Pentest_Track's title, level badge, duration, and description in the step header.
3. WHEN a user selects playlists for the Web_Pentest_Track in the PlaylistWizard, THE PlaylistWizard SHALL persist those selections to `localStorage` under the key `track_playlists`.
4. WHEN the PlaylistWizard reaches the Summary step, THE PlaylistWizard SHALL display the Web_Pentest_Track alongside all other tracks with its selected playlist count.
5. IF the Web_Pentest_Track has `isLocked: true`, THEN THE PlaylistWizard SHALL exclude it from the wizard steps.

---

### Requirement 5: Track Ordering and Placement

**User Story:** As a learner browsing the Learning Tracks page, I want the Web Penetration Testing track to appear among the intermediate tracks, so that the page layout groups tracks by difficulty level logically.

#### Acceptance Criteria

1. THE `learningPaths` array SHALL position the Web_Pentest_Track within the intermediate section, after the beginner tracks and before the advanced tracks.
2. WHEN the Learning_Tracks_Page renders all tracks without filters, THE Web_Pentest_Track SHALL appear in the intermediate group alongside "Jr Penetration Tester" and "SOC Analyst Level 1".

---

### Requirement 6: Track Content Placeholder Structure

**User Story:** As a content author, I want the Web Penetration Testing track to have a well-defined placeholder structure for modules, so that I can add lessons to it later without restructuring the data.

#### Acceptance Criteria

1. THE Web_Pentest_Track's `contentModules` array SHALL be empty at initial implementation, ready to accept module objects matching the schema used by other tracks.
2. THE Web_Pentest_Track's `youtubePlaylists` array SHALL be empty at initial implementation, ready to accept playlist objects assigned via the PlaylistWizard.
3. THE Web_Pentest_Track SHALL include a `duration` field with a reasonable placeholder value (e.g., `'40 Hours'`).
4. THE Web_Pentest_Track SHALL include a `modules` field with a value of `0` as a placeholder until content is added.
5. THE Web_Pentest_Track SHALL include a `students` field initialized to `0`.
