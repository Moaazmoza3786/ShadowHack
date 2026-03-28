const fs = require('fs');

// Mock browser global if needed, though module.exports should handle it
global.window = {};

try {
    const UnifiedLearningData = require('./unified-learning-data.js');

    const hierarchy = UnifiedLearningData.paths.map(track => {
        return {
            track_name: track.name,
            type: track.type || 'standard', // Added type for context
            paths: (track.units || []).map(unit => {
                return {
                    path_name: unit.name,
                    courses: (unit.rooms || []).map(room => {
                        // Attempt to extract description 
                        let desc = room.description || "";
                        if (!desc && room.content) {
                            // Simple strip tags if content is HTML
                            desc = room.content.replace(/<[^>]*>?/gm, '').substring(0, 100) + "...";
                        }

                        return {
                            course_title: room.title,
                            description: desc,
                            difficulty: room.difficulty || "unknown",
                            type: room.type || "unknown"
                        };
                    })
                };
            })
        };
    });

    console.log(JSON.stringify(hierarchy, null, 2));

} catch (error) {
    console.error("Error extracting hierarchy:", error);
}
