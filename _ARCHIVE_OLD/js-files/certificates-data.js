// ==================== CERTIFICATES DATA ====================

const certificatesData = {
    // Certificate Types
    types: {
        course_completion: {
            title: 'Certificate of Completion',
            description: 'Awarded for completing a full learning path.',
            icon: 'graduation-cap',
            color: '#4e73df' // Primary Blue
        },
        skill_badge: {
            title: 'Skill Badge',
            description: 'Awarded for demonstrating proficiency in a specific skill.',
            icon: 'medal',
            color: '#1cc88a' // Success Green
        },
        achievement: {
            title: 'Achievement Award',
            description: 'Awarded for unlocking a significant achievement.',
            icon: 'trophy',
            color: '#f6c23e' // Warning Yellow
        }
    },

    // Mock Data for available certificates (in a real app, this would come from backend)
    available: [
        {
            id: 'cert_web_fundamentals',
            type: 'course_completion',
            name: 'Web Hacking Fundamentals',
            description: 'Mastery of core web security concepts including HTTP, Cookies, and basic vulnerabilities.',
            criteria: 'Complete "Web Fundamentals" Learning Path'
        },
        {
            id: 'cert_sql_injection',
            type: 'skill_badge',
            name: 'SQL Injection Specialist',
            description: 'Demonstrated ability to identify and exploit various SQL Injection vulnerabilities.',
            criteria: 'Complete all SQL Injection Labs'
        },
        {
            id: 'cert_xss_master',
            type: 'skill_badge',
            name: 'XSS Master',
            description: 'Proficiency in detecting and exploiting Cross-Site Scripting vulnerabilities.',
            criteria: 'Complete all XSS Labs'
        },
        {
            id: 'cert_elite_hacker',
            type: 'achievement',
            name: 'Elite Hacker Status',
            description: 'Reached Level 10: Cyber Legend.',
            criteria: 'Reach Level 10'
        }
    ]
};

// Export for usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = certificatesData;
}
