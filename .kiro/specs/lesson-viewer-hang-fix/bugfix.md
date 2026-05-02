# Bugfix Requirements Document

## Introduction

Clicking a lesson in the Curriculum causes the site to hang/freeze. The root cause is a combination of three issues in `LessonViewer.jsx`: an infinite loop in the MDX parser when an `<InfoBox>` tag is unclosed, synchronous parsing blocking the main thread render, and no timeout guard on the lesson loader leaving the spinner stuck indefinitely.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN an MDX file contains an `<InfoBox>` tag with no matching `</InfoBox>` closing tag THEN the system enters an infinite while loop in `parseMDX()`, blocking the main thread and freezing the entire page.

1.2 WHEN a lesson is clicked and `parseMDX(content)` is called synchronously during render THEN the system blocks the React render cycle for the duration of parsing, causing the UI to hang for large MDX files.

1.3 WHEN `loadLesson()` is called and the dynamic import never resolves or rejects THEN the system never calls `setLoading(false)`, leaving the loading spinner displayed indefinitely with no fallback.

### Expected Behavior (Correct)

2.1 WHEN an MDX file contains an unclosed `<InfoBox>` tag THEN the system SHALL exit the multi-line InfoBox loop safely (using a max iterations guard or strict bounds check) and continue parsing the rest of the document without hanging.

2.2 WHEN a lesson is clicked THEN the system SHALL parse MDX content inside a `useEffect` after loading completes and store the result in state, so that parsing never blocks the render cycle.

2.3 WHEN `loadLesson()` has not resolved within 5 seconds THEN the system SHALL cancel the pending load, set loading to false, and display a "Content coming soon" fallback message.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN an MDX file contains a properly closed `<InfoBox type="...">...</InfoBox>` tag THEN the system SHALL CONTINUE TO parse and render the InfoBox component correctly.

3.2 WHEN a lesson file loads successfully within the timeout window THEN the system SHALL CONTINUE TO display the fully parsed MDX content as before.

3.3 WHEN a lesson file does not exist or `loadLesson()` rejects THEN the system SHALL CONTINUE TO display the "Content coming soon" fallback message.

3.4 WHEN a lesson is loading THEN the system SHALL CONTINUE TO display the spinner until loading is complete or the timeout is reached.
