# Requirements Document

## Introduction

This feature adds a new learning track called "Programming for Penetration Testers" to the BreachLabs/StudyHub cybersecurity learning platform. The track teaches programming skills directly applicable to penetration testing — Python scripting, Bash automation, and tool development — and appears alongside existing beginner tracks on the Learning Tracks page. It also participates in the PlaylistWizard so users can assign YouTube playlists to it. Content modules will be populated later via the wizard.

## Glossary

- **Platform**: The BreachLabs/StudyHub cybersecurity learning platform (React frontend + Python backend)
- **Learning_Tracks_Page**: The `/learning-tracks` route rendered by `LearningTracks.jsx`, which displays all learning paths from `learning-paths-data.js`
- **Learning_Path**: A structured entry in the `learningPaths` array in `learning-paths-data.js`, containing id, title, titleAr, description, descriptionAr, level, duration, modules, students, icon, skills, certGoals, contentModules, and youtubePlaylists fields
- **Track**: Synonym for Learning_Path used in UI context
- **PlaylistWizard**: The `/playlist-wizard` route that iterates over all non-locked tracks and lets users assign YouTube playlists to each
- **Programming_Track**: The new "Programming for Penetration Testers" Learning_Path being added
- **learning-paths-data.js**: The data file at `study-hub-react/src/data/learning-paths-data.js` that exports the `learningPaths` array
- **Bilingual_Support**: The platform's requirement to display content in both English and Arabic

---

## Requirements

### Requirement 1: Add Programming Track to Learning Paths Data

**User Story:** As a platform administrator, I want the "Programming for Penetration Testers" track defined in `learning-paths-data.js`, so that it is available to all parts of the platform that consume the `learningPaths` array.

#### Acceptance Criteria

1. THE `learning-paths-data.js` SHALL contain a new Learning_Path entry with `id: 'programming-for-pen-testers'`.
2. THE Programming_Track SHALL have `level: 'beginner'` so it appears alongside the "Pre Security" track in the beginner tier.
3. THE Programming_Track SHALL include an `icon` imported from `lucide-react` that is semantically appropriate for programming (e.g., `Code` or `Terminal`).
4. THE Programming_Track SHALL include a `skills` array containing at minimum: `['Python', 'Bash', 'Scripting', 'Tool Development']`.
5. THE Programming_Track SHALL include `certGoals` referencing at least one relevant certification (e.g., `['eJPT', 'OSCP']`).
6. THE Programming_Track SHALL have `isLocked` set to `false` (or omitted) so it is accessible and not shown as "COMING SOON".
7. THE Programming_Track SHALL include an empty `contentModules` array as a placeholder for future content.
8. THE Programming_Track SHALL include an empty `youtubePlaylists` array as a placeholder for wizard-assigned playlists.

---

### Requirement 2: Bilingual Track Metadata

**User Story:** As an Arabic-speaking learner, I want the Programming Track to display its title and description in Arabic, so that I can understand the track in my preferred language.

#### Acceptance Criteria

1. THE Programming_Track SHALL include a `titleAr` field with an Arabic translation of the track title.
2. THE Programming_Track SHALL include a `descriptionAr` field with an Arabic translation of the track description.
3. WHEN the platform language is set to Arabic, THE Learning_Tracks_Page SHALL display `titleAr` and `descriptionAr` for the Programming_Track.
4. WHEN the platform language is set to Arabic, THE PlaylistWizard SHALL display `titleAr` and `descriptionAr` for the Programming_Track in the track header.

---

### Requirement 3: Track Visibility on Learning Tracks Page

**User Story:** As a learner, I want to see the "Programming for Penetration Testers" track on the Learning Tracks page, so that I can discover and start the track.

#### Acceptance Criteria

1. WHEN a user navigates to the Learning Tracks page, THE Learning_Tracks_Page SHALL render a card for the Programming_Track.
2. WHEN a user filters by "Beginner" level, THE Learning_Tracks_Page SHALL include the Programming_Track card in the filtered results.
3. WHEN a user searches for "Python" or "programming", THE Learning_Tracks_Page SHALL include the Programming_Track card in the search results.
4. WHEN a user clicks the Programming_Track card, THE Platform SHALL navigate to `/track/programming-for-pen-testers`.
5. THE Programming_Track card SHALL display the ENTRY level badge consistent with other beginner tracks.

---

### Requirement 4: Track Participation in PlaylistWizard

**User Story:** As a learner, I want the Programming Track to appear in the PlaylistWizard, so that I can assign YouTube playlists to it for self-directed study.

#### Acceptance Criteria

1. WHEN the PlaylistWizard loads, THE PlaylistWizard SHALL include the Programming_Track as one of its steps.
2. WHILE iterating tracks in the PlaylistWizard, THE PlaylistWizard SHALL display the Programming_Track's title, level badge, duration, and description in the step header.
3. WHEN a user selects playlists for the Programming_Track in the PlaylistWizard, THE PlaylistWizard SHALL persist those selections to `localStorage` under the key `track_playlists`.
4. WHEN the PlaylistWizard reaches the Summary step, THE PlaylistWizard SHALL display the Programming_Track alongside all other tracks with its selected playlist count.
5. IF the Programming_Track has `isLocked: true`, THEN THE PlaylistWizard SHALL exclude it from the wizard steps. (This criterion ensures the existing lock-filtering logic continues to work correctly.)

---

### Requirement 5: Track Ordering and Placement

**User Story:** As a learner browsing the Learning Tracks page, I want the Programming Track to appear near other beginner tracks, so that the page layout groups tracks by difficulty level logically.

#### Acceptance Criteria

1. THE `learningPaths` array SHALL position the Programming_Track within the beginner section, adjacent to or after the "Pre Security" track.
2. WHEN the Learning_Tracks_Page renders all tracks without filters, THE Programming_Track SHALL appear in the beginner group alongside "Pre Security" and "Web Fundamentals".

---

### Requirement 6: Track Content Placeholder Structure

**User Story:** As a content author, I want the Programming Track to have a well-defined placeholder structure for modules, so that I can add lessons to it later without restructuring the data.

#### Acceptance Criteria

1. THE Programming_Track's `contentModules` array SHALL be empty at initial implementation, ready to accept module objects matching the schema used by other tracks.
2. THE Programming_Track's `youtubePlaylists` array SHALL be empty at initial implementation, ready to accept playlist objects assigned via the PlaylistWizard.
3. THE Programming_Track SHALL include a `duration` field with a reasonable placeholder value (e.g., `'30 Hours'`).
4. THE Programming_Track SHALL include a `modules` field with a value of `0` or a planned module count placeholder.
5. THE Programming_Track SHALL include a `students` field initialized to `0` or a reasonable seed value.
