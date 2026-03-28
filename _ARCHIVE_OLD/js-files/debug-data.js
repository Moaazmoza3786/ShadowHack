
console.log("=== DEBUG DATA INSPECTION ===");
if (window.UnifiedLearningData) {
    console.log("UnifiedLearningData exists.");
    console.log("Version:", window.UnifiedLearningData._version);
    console.log("Courses Count:", window.UnifiedLearningData.courses ? window.UnifiedLearningData.courses.length : 0);
    console.log("First Course ID:", window.UnifiedLearningData.courses && window.UnifiedLearningData.courses.length > 0 ? window.UnifiedLearningData.courses[0].id : "N/A");

    // Check for specific course IDs we expect
    const expected = ['intro-cybersecurity', 'web-pentesting-beginner'];
    expected.forEach(id => {
        const found = window.UnifiedLearningData.getCourseById(id);
        console.log(`Check for ${id}:`, found ? "FOUND" : "NOT FOUND");
    });
} else {
    console.error("UnifiedLearningData is MISSING or NULL!");
}
console.log("=============================");
