/**
 * Personalized Recommendations Engine
 * Analyzes user behavior and suggests content based on learning patterns
 */

class RecommendationEngine {
    constructor() {
        this.userProfile = {};
        this.recommendations = [];
        this.learningHistory = [];
    }

    /**
     * Analyze user profile and learning patterns
     */
    analyzeUserProfile(userData) {
        this.userProfile = {
            level: userData.level || 1,
            completedLabs: userData.completedLabs || [],
            failedAttempts: userData.failedAttempts || [],
            averageCompletionTime: userData.avgTime || 0,
            preferredCategories: this.getPreferredCategories(userData.completedLabs),
            skillGaps: this.identifySkillGaps(userData),
            learningStyle: this.detectLearningStyle(userData),
            engagementScore: this.calculateEngagementScore(userData),
        };

        return this.userProfile;
    }

    /**
     * Identify which categories user prefers
     */
    getPreferredCategories(completedLabs) {
        const categoryCount = {};

        completedLabs.forEach(lab => {
            const category = lab.category || 'other';
            categoryCount[category] = (categoryCount[category] || 0) + 1;
        });

        return Object.entries(categoryCount)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([category]) => category);
    }

    /**
     * Identify skill gaps based on performance
     */
    identifySkillGaps(userData) {
        const skillScores = {};

        // Analyze completed vs failed attempts
        userData.completedLabs?.forEach(lab => {
            skillScores[lab.category] = (skillScores[lab.category] || 0) + 10;
        });

        userData.failedAttempts?.forEach(attempt => {
            skillScores[attempt.category] = (skillScores[attempt.category] || 0) - 5;
        });

        // Return skills with lowest scores (gaps)
        return Object.entries(skillScores)
            .sort((a, b) => a[1] - b[1])
            .slice(0, 3)
            .map(([skill, score]) => ({ skill, score }));
    }

    /**
     * Detect learning style based on behavior
     */
    detectLearningStyle(userData) {
        let style = 'balanced';

        const videosVsText = (userData.videosWatched || 0) / Math.max((userData.articlesRead || 0), 1);
        const practiceVsTheory = (userData.labsCompleted || 0) / Math.max((userData.coursesCompleted || 0), 1);

        if (videosVsText > 2) style = 'visual';
        else if (practiceVsTheory > 2) style = 'practical';
        else if (userData.articlesRead > userData.videosWatched) style = 'reading';

        return style;
    }

    /**
     * Calculate engagement score
     */
    calculateEngagementScore(userData) {
        const score =
            (userData.completedLabs?.length || 0) * 10 +
            (userData.courseProgress || 0) * 5 +
            (userData.dailyStreak || 0) * 3;

        return Math.min(100, score);
    }

    /**
     * Generate personalized recommendations
     */
    generateRecommendations(allCourses, allLabs, userProfile) {
        this.recommendations = [];

        // 1. Recommendations based on skill gaps
        const gapRecommendations = this.recommendBySkillGaps(allLabs, userProfile.skillGaps);

        // 2. Recommendations based on learning style
        const styleRecommendations = this.recommendByLearningStyle(allCourses, userProfile.learningStyle);

        // 3. Recommendations based on difficulty progression
        const difficultyRecommendations = this.recommendByProgression(allLabs, userProfile.level);

        // 4. Trending/Popular content
        const trendingRecommendations = this.getTopRatedContent(allCourses, allLabs);

        // Combine and rank
        this.recommendations = [
            ...gapRecommendations.map((r, i) => ({ ...r, score: 100 - i * 10 })),
            ...styleRecommendations.map((r, i) => ({ ...r, score: 80 - i * 8 })),
            ...difficultyRecommendations.map((r, i) => ({ ...r, score: 70 - i * 7 })),
            ...trendingRecommendations.map((r, i) => ({ ...r, score: 60 - i * 6 })),
        ]
            .filter((r, idx, arr) => arr.findIndex(item => item.id === r.id) === idx) // Remove duplicates
            .sort((a, b) => b.score - a.score)
            .slice(0, 12); // Top 12 recommendations

        return this.recommendations;
    }

    /**
     * Recommend labs to fill skill gaps
     */
    recommendBySkillGaps(labs, skillGaps) {
        const recommendations = [];

        skillGaps.forEach(gap => {
            const relatedLabs = labs.filter(lab =>
                lab.category === gap.skill &&
                lab.difficulty === 'Medium'
            );
            recommendations.push(...relatedLabs.slice(0, 3));
        });

        return recommendations;
    }

    /**
     * Recommend based on learning style
     */
    recommendByLearningStyle(courses, learningStyle) {
        const recommendations = [];

        if (learningStyle === 'visual') {
            recommendations.push(...courses.filter(c => c.hasVideos).slice(0, 3));
        } else if (learningStyle === 'practical') {
            recommendations.push(...courses.filter(c => c.hasLabs).slice(0, 3));
        } else if (learningStyle === 'reading') {
            recommendations.push(...courses.filter(c => c.hasArticles).slice(0, 3));
        }

        return recommendations;
    }

    /**
     * Recommend based on difficulty progression
     */
    recommendByProgression(labs, currentLevel) {
        const nextDifficulty = currentLevel < 3 ? 'Easy' : currentLevel < 6 ? 'Medium' : 'Hard';

        return labs
            .filter(lab =>
                lab.difficulty === nextDifficulty &&
                !this.userProfile.completedLabs?.some(cl => cl.id === lab.id)
            )
            .slice(0, 4);
    }

    /**
     * Get top-rated content for trending recommendations
     */
    getTopRatedContent(courses, labs) {
        const combined = [
            ...courses.map(c => ({ ...c, type: 'course' })),
            ...labs.map(l => ({ ...l, type: 'lab' })),
        ];

        return combined
            .filter(item => item.rating >= 4.5)
            .sort((a, b) => b.rating - a.rating)
            .slice(0, 4);
    }

    /**
     * Get recommendations for a specific user
     */
    async getUserRecommendations(userId, limit = 10) {
        try {
            const response = await fetch(`/api/recommendations/user/${userId}?limit=${limit}`);
            const data = await response.json();
            return data.recommendations || [];
        } catch (error) {
            console.error('Error fetching recommendations:', error);
            return [];
        }
    }

    /**
     * Log user interaction for better recommendations
     */
    logInteraction(userId, action, itemId, itemType) {
        // In a real app, this would be sent to backend
        const interaction = {
            userId,
            action, // 'view', 'complete', 'start', 'fail'
            itemId,
            itemType, // 'lab', 'course', 'path'
            timestamp: new Date(),
        };

        this.learningHistory.push(interaction);
    }

    /**
     * Get personalized learning paths
     */
    getPersonalizedLearningPaths(userProfile, availablePaths) {
        return availablePaths.map(path => ({
            ...path,
            relevanceScore: this.calculatePathRelevance(path, userProfile),
            estimatedDuration: this.estimateLearningTime(path, userProfile),
            matchedSkills: path.skills.filter(s =>
                userProfile.preferredCategories.includes(s)
            ),
        }))
            .sort((a, b) => b.relevanceScore - a.relevanceScore);
    }

    /**
     * Calculate how relevant a path is for the user
     */
    calculatePathRelevance(path, userProfile) {
        let score = 0;

        // Category match
        const categoryMatches = path.categories.filter(c =>
            userProfile.preferredCategories.includes(c)
        ).length;
        score += categoryMatches * 25;

        // Difficulty match
        if (path.difficulty === this.getDifficultyLevel(userProfile.level)) {
            score += 20;
        }

        // Skills match user interests
        const skillMatches = path.skills.filter(s =>
            userProfile.skillGaps.some(gap => gap.skill === s)
        ).length;
        score += skillMatches * 15;

        // Learning style compatibility
        if (path.learningStyle === userProfile.learningStyle) {
            score += 10;
        }

        return Math.min(100, score);
    }

    /**
     * Estimate time needed to complete a path
     */
    estimateLearningTime(path, userProfile) {
        const baseTime = path.estimatedHours || 20;
        const userSpeed = userProfile.engagementScore / 50; // Faster users have higher engagement
        return Math.round(baseTime / Math.max(userSpeed, 0.5));
    }

    /**
     * Get difficulty level based on user progress
     */
    getDifficultyLevel(userLevel) {
        if (userLevel < 3) return 'Beginner';
        if (userLevel < 6) return 'Intermediate';
        if (userLevel < 9) return 'Advanced';
        return 'Expert';
    }
}

// Create singleton instance
const recommendationEngine = new RecommendationEngine();

export default recommendationEngine;
