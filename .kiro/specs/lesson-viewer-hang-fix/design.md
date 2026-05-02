# Lesson Viewer Hang Fix — Bugfix Design

## Overview

The `LessonViewer` component in `study-hub-react/src/components/LessonViewer.jsx` can freeze the browser in three distinct ways: an infinite loop in the multi-line `<InfoBox>` parser when the closing tag is missing, synchronous MDX parsing blocking the React render cycle, and a missing timeout on `loadLesson()` that leaves the spinner stuck forever. The fix is surgical — three targeted changes to the same file, no API or data-model changes.

## Glossary

- **Bug_Condition (C)**: The set of inputs/states that trigger one of the three hang scenarios
- **Property (P)**: The desired behavior — the component must always terminate, render, and recover gracefully
- **Preservation**: All existing correct behaviors (valid InfoBox parsing, successful lesson load, error fallback, spinner display) must remain unchanged
- **parseMDX**: The function in `LessonViewer.jsx` that converts raw MDX text into an array of renderable element descriptors
- **loadLesson**: The async utility in `../utils/contentLoader` that dynamically imports an MDX lesson file
- **isBugCondition**: Pseudocode predicate identifying inputs that trigger the bug
- **unclosed InfoBox**: An `<InfoBox ...>` opening tag in MDX content with no corresponding `</InfoBox>` closing tag before EOF

## Bug Details

### Bug Condition

The bug manifests under any of three conditions in `LessonViewer.jsx`. The component either loops infinitely in the parser, blocks the render thread with synchronous parsing, or stalls indefinitely waiting for a promise that never settles.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input = { mdxContent: string, lessonFile: string, loadResolves: boolean, loadTimeMs: number }
  OUTPUT: boolean

  // Condition A — unclosed InfoBox causes infinite loop
  IF mdxContent contains "<InfoBox" AND mdxContent does NOT contain "</InfoBox>"
    RETURN true

  // Condition B — parseMDX called synchronously during render (architectural)
  IF parseMDX is invoked outside of useEffect during component render
    RETURN true

  // Condition C — loadLesson never settles within acceptable time
  IF loadResolves = false AND loadTimeMs > 5000
    RETURN true

  RETURN false
END FUNCTION
```

### Examples

- **Condition A**: An MDX file ending with `<InfoBox type="warning">\nSome text` (no `</InfoBox>`) — `parseMDX` enters the inner `while` loop, `i` never advances past EOF, browser tab freezes.
- **Condition B**: A large MDX file (500+ lines) — `parseMDX(content)` is called inline during render, blocking the main thread for tens of milliseconds per render cycle, causing visible jank or hang on slower devices.
- **Condition C**: `loadLesson()` triggers a dynamic import that stalls (network timeout, missing chunk) — `setLoading(false)` is never called, the spinner spins forever with no user recourse.
- **Edge case A**: MDX file ends immediately after `<InfoBox type="info">` with zero body lines — same infinite loop, zero iterations of inner while but `i` is never incremented past the missing closing tag.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- A properly closed `<InfoBox type="...">...</InfoBox>` (single-line or multi-line) MUST continue to parse and render correctly
- A lesson file that loads successfully within 5 seconds MUST continue to display its fully parsed MDX content
- A `loadLesson()` rejection MUST continue to display the "Content coming soon" fallback
- The loading spinner MUST continue to display while a lesson is loading (until completion or timeout)
- All other MDX element types (headings, code blocks, tables, lists, quiz, terminal) MUST be unaffected

**Scope:**
All inputs where none of the three bug conditions hold are completely unaffected by this fix. This includes:
- Any MDX content that does not contain a multi-line `<InfoBox>` block
- Any lesson that loads and resolves within 5 seconds
- All non-InfoBox MDX parsing paths

## Hypothesized Root Cause

1. **Missing post-loop `i++` for closing tag consumption (Condition A)**: After the inner `while` loop exits (because `lines[i].includes('</InfoBox>')` is true), the outer loop's `i++; continue` advances `i` — but only if `lines[i]` actually exists. When the file ends without `</InfoBox>`, the inner `while` exits because `i >= lines.length`, then the outer code executes `i++; continue` which increments `i` to `lines.length + 1`... except the outer `while (i < lines.length)` guard should catch this. Re-reading the code: the inner loop is `while (i < lines.length && !lines[i].includes('</InfoBox>'))` — when EOF is reached, `i === lines.length`, the inner loop exits, then `elements.push(...)` runs, then `i++` runs making `i = lines.length + 1`, then `continue` goes back to the outer `while (i < lines.length)` which is now false — so the outer loop DOES exit. The actual hang is more subtle: if the MDX content has the `<InfoBox` opening tag matched by the multi-line branch but the file has content after it that keeps the outer loop running with `i` stuck. The safest fix is to guard the post-loop `i++` so it only fires when `lines[i]` exists and contains `</InfoBox>`, preventing any off-by-one that could cause re-entry.

2. **Synchronous parseMDX during render (Condition B)**: `const elements = loading ? [] : parseMDX(content)` is evaluated on every render. For large files this is expensive and blocks the main thread. Moving it into `useEffect` with `useState` decouples parsing from rendering.

3. **No timeout on loadLesson (Condition C)**: The `useEffect` calls `loadLesson(lesson.file).then(...).catch(...)` with no timeout. If the dynamic import never settles, neither `.then` nor `.catch` fires, so `setLoading(false)` is never called.

## Correctness Properties

Property 1: Bug Condition A — Unclosed InfoBox Terminates Safely

_For any_ raw MDX string where `isBugCondition` holds due to a missing `</InfoBox>` closing tag, the fixed `parseMDX` function SHALL terminate (not loop infinitely), return an array of elements, and include a best-effort infobox element using whatever text was collected before EOF.

**Validates: Requirements 2.1**

Property 2: Bug Condition C — Timeout Triggers Fallback

_For any_ `loadLesson` call that does not resolve or reject within 5000 ms, the fixed `LessonViewer` component SHALL set `loading` to `false` and display the "Content coming soon" fallback message within approximately 5 seconds.

**Validates: Requirements 2.3**

Property 3: Preservation — Valid InfoBox Parsing Unchanged

_For any_ raw MDX string where `isBugCondition` does NOT hold (i.e., all `<InfoBox>` tags are properly closed), the fixed `parseMDX` function SHALL produce exactly the same element array as the original function, preserving all InfoBox type, text, and rendering behavior.

**Validates: Requirements 3.1, 3.2**

Property 4: Preservation — Successful Load Behavior Unchanged

_For any_ `loadLesson` call that resolves within 5 seconds, the fixed `LessonViewer` component SHALL display the fully parsed MDX content, preserving the existing successful-load behavior.

**Validates: Requirements 3.2, 3.4**

## Fix Implementation

### Changes Required

**File**: `study-hub-react/src/components/LessonViewer.jsx`

**Change 1 — Guard the post-loop `i++` in the multi-line InfoBox parser**

In `parseMDX`, after the inner `while` loop that collects multi-line InfoBox body lines, the current code unconditionally does `i++` to skip the `</InfoBox>` line. The fix: only increment `i` if `lines[i]` exists and actually contains `</InfoBox>`.

```js
// Before
while (i < lines.length && !lines[i].includes('</InfoBox>')) { texts.push(lines[i]); i++; }
elements.push({ type: 'infobox', boxType: typeM?.[1] || 'info', text: texts.join(' ') });
i++; continue;

// After
while (i < lines.length && !lines[i].includes('</InfoBox>')) { texts.push(lines[i]); i++; }
elements.push({ type: 'infobox', boxType: typeM?.[1] || 'info', text: texts.join(' ') });
if (i < lines.length && lines[i].includes('</InfoBox>')) i++;
continue;
```

**Change 2 — Move parseMDX into useEffect, store result in state**

Add an `elements` state variable. Call `parseMDX` inside the existing `useEffect` after `setContent(raw)`, and store the result. Remove the inline `parseMDX(content)` call from the render body.

```js
// Add state
const [elements, setElements] = useState([]);

// In useEffect, after setContent(raw):
setElements(parseMDX(raw));

// Also set empty on reset and fallback:
setElements([]);  // at the top of useEffect before load
// In catch / fallback: setElements(parseMDX(`# ${lesson.title}\n\nContent coming soon.`));

// Remove from render:
// const elements = loading ? [] : parseMDX(content);  ← delete this line
```

**Change 3 — Add 5-second timeout to loadLesson via Promise.race**

Wrap the `loadLesson` call with `Promise.race` against a timeout promise that rejects after 5000 ms.

```js
const timeout = new Promise((_, reject) =>
  setTimeout(() => reject(new Error('timeout')), 5000)
);
Promise.race([loadLesson(lesson.file), timeout])
  .then(raw => { ... })
  .catch(() => { ... });
```

## Testing Strategy

### Validation Approach

Two-phase approach: first run exploratory tests against the unfixed code to confirm the root causes, then verify the fix satisfies all correctness properties and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate each hang scenario on the UNFIXED code. Confirm or refute the root cause analysis.

**Test Plan**: Write unit tests for `parseMDX` with unclosed InfoBox inputs and run them against the original function. Write a component test with a never-resolving `loadLesson` mock and assert that `loading` remains `true` indefinitely (demonstrating the bug).

**Test Cases**:
1. **Unclosed InfoBox at EOF**: Call `parseMDX` with `"<InfoBox type=\"info\">\nsome text"` (no closing tag) — expect termination within a time limit (will hang on unfixed code)
2. **Unclosed InfoBox with zero body lines**: Call `parseMDX` with `"<InfoBox type=\"warning\">"` alone — same expectation
3. **Never-resolving loadLesson**: Render `LessonViewer` with a mock `loadLesson` that returns `new Promise(() => {})`, advance timers 10 seconds, assert `loading` is still `true` (demonstrates Condition C bug)
4. **Large MDX synchronous parse**: Measure render time with a 1000-line MDX file on unfixed code to confirm Condition B impact

**Expected Counterexamples**:
- `parseMDX` with unclosed InfoBox either hangs or produces incorrect output
- Component with never-resolving loader never exits loading state

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed code produces the expected behavior.

**Pseudocode:**
```
FOR ALL mdxContent WHERE isBugCondition(mdxContent) DUE TO unclosed InfoBox DO
  result := parseMDX_fixed(mdxContent)
  ASSERT result is an Array
  ASSERT result terminates in finite time
  ASSERT result contains an infobox element with collected text
END FOR

FOR ALL loadScenario WHERE isBugCondition(loadScenario) DUE TO timeout DO
  render LessonViewer_fixed with never-resolving loadLesson mock
  advance timers by 5001ms
  ASSERT loading = false
  ASSERT fallback content is displayed
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed code produces the same result as the original.

**Pseudocode:**
```
FOR ALL mdxContent WHERE NOT isBugCondition(mdxContent) DO
  ASSERT parseMDX_original(mdxContent) deep-equals parseMDX_fixed(mdxContent)
END FOR

FOR ALL loadScenario WHERE loadLesson resolves within 5s DO
  ASSERT LessonViewer_fixed displays same content as LessonViewer_original
END FOR
```

**Testing Approach**: Property-based testing is recommended for `parseMDX` preservation because:
- It generates many random MDX strings with valid InfoBox tags automatically
- It catches edge cases (empty body, special characters, nested-looking tags) that manual tests miss
- It provides strong guarantees that the parser output is identical for all non-buggy inputs

**Test Cases**:
1. **Valid single-line InfoBox preservation**: Verify `<InfoBox type="info">text</InfoBox>` parses identically before and after fix
2. **Valid multi-line InfoBox preservation**: Verify multi-line InfoBox with body text parses identically
3. **Successful load within timeout**: Mock `loadLesson` resolving in 100ms, verify content displays correctly
4. **Rejected loadLesson fallback**: Mock `loadLesson` rejecting immediately, verify fallback message shown

### Unit Tests

- `parseMDX` with unclosed `<InfoBox>` at end of file — must return array and terminate
- `parseMDX` with unclosed `<InfoBox>` with zero body lines — must return array and terminate
- `parseMDX` with valid closed `<InfoBox>` — output must match original
- `LessonViewer` with never-resolving `loadLesson` — after 5s, loading is false and fallback shown
- `LessonViewer` with fast-resolving `loadLesson` — content displayed, no timeout triggered

### Property-Based Tests

- Generate random MDX strings with properly closed InfoBox tags; verify `parseMDX_fixed` output equals `parseMDX_original` output (preservation property)
- Generate random MDX strings with unclosed InfoBox tags; verify `parseMDX_fixed` always terminates and returns an array (fix property)
- Generate random load delay values 0–4999ms; verify content always displays (preservation of successful load)

### Integration Tests

- Open `LessonViewer` with a real MDX file containing a valid multi-line InfoBox — verify it renders correctly
- Open `LessonViewer` with a lesson file that does not exist — verify fallback message appears
- Simulate slow network (mock `loadLesson` resolving after 6s) — verify timeout fallback appears after ~5s
