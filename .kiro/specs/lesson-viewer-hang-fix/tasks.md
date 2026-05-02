# Implementation Plan

- [ ] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Unclosed InfoBox Infinite Loop & Timeout Hang
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bugs exist
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the hang scenarios exist
  - **Scoped PBT Approach**: Scope to concrete failing cases — unclosed InfoBox at EOF, and never-resolving loadLesson after 5s
  - Test A: Call `parseMDX` with `"<InfoBox type=\"info\">\nsome text"` (no closing tag) — assert it terminates and returns an array (from Bug Condition A in design)
  - Test B: Call `parseMDX` with `"<InfoBox type=\"warning\">"` alone (zero body lines, no closing tag) — assert same
  - Test C: Render `LessonViewer` with a mock `loadLesson` returning `new Promise(() => {})`, advance timers 10 seconds, assert `loading` is still `true` (demonstrates Condition C bug)
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests FAIL (Test A/B hang or produce wrong output; Test C shows spinner stuck — this proves the bugs exist)
  - Document counterexamples found (e.g., "parseMDX hangs on unclosed InfoBox", "loading never becomes false after 10s")
  - Mark task complete when tests are written, run, and failures are documented
  - _Requirements: 1.1, 1.3_

- [ ] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Valid InfoBox Parsing and Successful Load Behavior Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe: `parseMDX('<InfoBox type="info">text</InfoBox>')` returns an infobox element with type "info" and text "text" on unfixed code
  - Observe: `parseMDX` with a multi-line InfoBox (properly closed) returns the correct infobox element on unfixed code
  - Observe: `LessonViewer` with `loadLesson` resolving in 100ms displays content correctly on unfixed code
  - Observe: `LessonViewer` with `loadLesson` rejecting immediately shows "Content coming soon" fallback on unfixed code
  - Write property-based test: for all MDX strings with properly closed `<InfoBox>` tags, `parseMDX` output is a valid array containing an infobox element (from Preservation Requirements in design)
  - Write property-based test: for all load delays 0–4999ms, `LessonViewer` displays content after load resolves
  - Verify all tests PASS on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [-] 3. Fix for LessonViewer hang (three targeted changes in LessonViewer.jsx)

  - [x] 3.1 Implement the fix
    - **Change 1**: In `parseMDX`, guard the post-loop `i++` so it only fires when `lines[i]` exists and contains `</InfoBox>` — replace `i++; continue;` after the inner while loop with `if (i < lines.length && lines[i].includes('</InfoBox>')) i++; continue;`
    - **Change 2**: Add `const [elements, setElements] = useState([])` state; move `parseMDX` call into the existing `useEffect` (call `setElements(parseMDX(raw))` after `setContent(raw)`, `setElements([])` on reset, and `setElements(parseMDX(...))` in catch/fallback); remove the inline `const elements = loading ? [] : parseMDX(content)` from the render body
    - **Change 3**: Wrap `loadLesson(lesson.file)` with `Promise.race` against a `setTimeout` reject of 5000ms so a stalled import triggers the catch handler and calls `setLoading(false)`
    - _Bug_Condition: isBugCondition(input) where mdxContent has unclosed `<InfoBox>` (Condition A), parseMDX called synchronously during render (Condition B), or loadLesson never settles within 5s (Condition C)_
    - _Expected_Behavior: parseMDX terminates and returns array for all inputs; loading becomes false within ~5s for any loadLesson call; MDX parsing never blocks the render cycle_
    - _Preservation: Valid closed InfoBox tags parse identically; successful loads within 5s display full content; rejected loads show fallback; spinner shows during load_
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.4_

  - [ ] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Unclosed InfoBox Terminates & Timeout Triggers Fallback
    - **IMPORTANT**: Re-run the SAME tests from task 1 — do NOT write new tests
    - The tests from task 1 encode the expected behavior
    - When these tests pass, it confirms the expected behavior is satisfied
    - Run bug condition exploration tests from step 1
    - **EXPECTED OUTCOME**: Tests PASS (confirms all three hang scenarios are fixed)
    - _Requirements: 2.1, 2.3_

  - [ ] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - Valid InfoBox Parsing and Successful Load Behavior Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions in valid InfoBox parsing, successful loads, error fallback, or spinner behavior)
    - Confirm all tests still pass after fix (no regressions)

- [x] 4. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
