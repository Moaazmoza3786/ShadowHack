# Implementation Plan: Web Penetration Testing Track

## Overview

Single data change: insert the `web-penetration-testing` track object into the `learningPaths` array in `study-hub-react/src/data/learning-paths-data.js`, after `soc-analyst-1` and before the advanced section.

## Tasks

- [x] 1. Insert web-penetration-testing track object into learningPaths
  - Open `study-hub-react/src/data/learning-paths-data.js`
  - Locate the `soc-analyst-1` entry in the `learningPaths` array
  - Insert the new track object immediately after `soc-analyst-1` and before the first advanced-level track
  - Use the `Bug` icon (already imported) as the `icon` field
  - Set all fields per the schema: `id`, `title`, `titleAr`, `description`, `descriptionAr`, `level: 'intermediate'`, `duration: '40 Hours'`, `modules: 0`, `students: 0`, `icon: Bug`, `skills`, `certGoals`, `contentModules: []`, `youtubePlaylists: []`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.1, 2.2, 5.1, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ]* 1.1 Write unit tests for the new track object shape
    - Import `learningPaths` and find the entry with `id: 'web-penetration-testing'`
    - Assert all required fields are present with correct types and values
    - Assert `skills` contains `['OWASP Top 10', 'Burp Suite', 'SQL Injection', 'XSS', 'IDOR']`
    - Assert `certGoals` contains `['eWPT', 'BSCP', 'OSWA']`
    - Assert `contentModules.length === 0` and `youtubePlaylists.length === 0`
    - Assert the track appears after `soc-analyst-1` and before the first `level: 'advanced'` track
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 1.8, 5.1, 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ]* 1.2 Write property test for level filter (Property 1)
    - **Property 1: Level filter includes all matching tracks**
    - **Validates: Requirements 3.2**

  - [ ]* 1.3 Write property test for search matching (Property 2)
    - **Property 2: Search matches title, description, and skills**
    - **Validates: Requirements 3.3**

  - [ ]* 1.4 Write property test for intermediate badge rendering (Property 3)
    - **Property 3: Intermediate tracks render the intermediate badge**
    - **Validates: Requirements 3.5**

  - [ ]* 1.5 Write property test for Arabic rendering (Property 4)
    - **Property 4: Arabic rendering uses titleAr and descriptionAr**
    - **Validates: Requirements 2.3, 2.4**

  - [ ]* 1.6 Write property test for locked tracks excluded from wizard (Property 5)
    - **Property 5: Locked tracks are excluded from PlaylistWizard**
    - **Validates: Requirements 4.5**

  - [ ]* 1.7 Write property test for wizard localStorage persistence (Property 6)
    - **Property 6: PlaylistWizard persists selections to localStorage**
    - **Validates: Requirements 4.3**

  - [ ]* 1.8 Write property test for wizard step metadata display (Property 7)
    - **Property 7: PlaylistWizard step displays required track metadata**
    - **Validates: Requirements 4.2**

- [x] 2. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The entire implementation is a single object insertion — no component, route, or backend changes are needed
- Property tests should use `fast-check` (JavaScript property-based testing library)
- Each property test should run a minimum of 100 iterations
