# Implementation Plan: Programming for Penetration Testers

## Overview

Single data change: insert a new track object into the `learningPaths` array in `study-hub-react/src/data/learning-paths-data.js`, positioned between `pre-security` and `web-fundamentals`.

## Tasks

- [x] 1. Insert the Programming for Penetration Testers track object
  - Open `study-hub-react/src/data/learning-paths-data.js`
  - Insert the following object between the `pre-security` entry and the `web-fundamentals` entry:
    ```js
    {
      id: 'programming-for-pen-testers',
      title: 'Programming for Penetration Testers',
      titleAr: 'البرمجة لمختبري الاختراق',
      description: 'Learn Python and Bash scripting to automate tasks, build custom tools, and supercharge your penetration testing workflow.',
      descriptionAr: 'تعلم البرمجة بـ Python وBash لأتمتة المهام وبناء أدوات مخصصة وتعزيز سير عمل اختبار الاختراق.',
      level: 'beginner',
      duration: '30 Hours',
      modules: 0,
      students: 0,
      icon: Code,
      skills: ['Python', 'Bash', 'Scripting', 'Tool Development'],
      certGoals: ['eJPT', 'OSCP'],
      contentModules: [],
      youtubePlaylists: [],
    },
    ```
  - The `Code` icon is already imported at the top of the file — no import changes needed
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.1, 2.2, 5.1, 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 2. Write unit tests for the new track entry
  - [x] 2.1 Write schema and value tests
    - Import `learningPaths` from `learning-paths-data.js`
    - Find the entry with `id: 'programming-for-pen-testers'` and assert:
      - All required fields are present with correct types
      - `level === 'beginner'`
      - `icon` is the `Code` component
      - `skills` contains `['Python', 'Bash', 'Scripting', 'Tool Development']`
      - `certGoals` contains `'eJPT'` and `'OSCP'`
      - `contentModules.length === 0`
      - `youtubePlaylists.length === 0`
      - `isLocked` is falsy
      - `duration === '30 Hours'`
      - `modules === 0`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 6.3, 6.4, 6.5_

  - [ ]* 2.2 Write array ordering test
    - Assert the programming track appears after `pre-security` and before `web-fundamentals` in the array
    - _Requirements: 5.1, 5.2_

- [ ] 3. Write property-based tests
  - [ ]* 3.1 Write property test for level filter
    - **Property 1: Level filter includes all matching tracks**
    - **Validates: Requirements 3.2**
    - Use `fast-check` to generate random subsets of `learningPaths` entries with `level === 'beginner'`; assert the filter function returns them when `selectedLevel === 'beginner'`

  - [ ]* 3.2 Write property test for search matching
    - **Property 2: Search matches title and description**
    - **Validates: Requirements 3.3**
    - For each track in `learningPaths`, generate random substrings of `title` and `description`; assert the filter function returns the track for each substring

  - [ ]* 3.3 Write property test for ENTRY badge
    - **Property 3: Beginner tracks render the ENTRY badge**
    - **Validates: Requirements 3.5**
    - For any track object with `level === 'beginner'`, render the badge logic and assert the output text is `'ENTRY'`

  - [ ]* 3.4 Write property test for Arabic rendering
    - **Property 4: Arabic rendering uses titleAr and descriptionAr**
    - **Validates: Requirements 2.3, 2.4**
    - For any track object with both `titleAr` and `descriptionAr`, render the component with `language='ar'` and assert the Arabic strings appear in the output

  - [ ]* 3.5 Write property test for locked track exclusion
    - **Property 5: Locked tracks are excluded from PlaylistWizard**
    - **Validates: Requirements 4.5**
    - Generate random arrays of track objects where some have `isLocked: true`; assert the wizard's filtered track list contains none of the locked tracks

  - [ ]* 3.6 Write property test for localStorage persistence
    - **Property 6: PlaylistWizard persists selections to localStorage**
    - **Validates: Requirements 4.3**
    - For any track id and any array of playlist ids, simulate a selection toggle and assert `localStorage` contains the expected ids under `track_playlists[trackId]`

  - [ ]* 3.7 Write property test for wizard step metadata display
    - **Property 7: PlaylistWizard step displays required track metadata**
    - **Validates: Requirements 4.2**
    - For any non-locked track object, render the `TrackStep` component and assert the rendered output contains the track's title, level, duration, and description

- [x] 4. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The entire implementation is a single object insertion — no component, route, or backend changes are needed
- Property tests require `fast-check` to be installed in the React project
