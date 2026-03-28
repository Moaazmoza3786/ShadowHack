/* ============================================================
   PLATFORM TAXONOMY - Study Hub Cybersecurity Platform
   Central definitions for difficulty levels, categories, and helpers
   ============================================================ */

const PlatformTaxonomy = {
    // ==================== DIFFICULTY LEVELS ====================
    difficulties: {
        basic: {
            id: 'basic',
            name: 'Basic',
            description: 'Theoretical concepts only, no complex labs',
            color: '#6b7280',
            icon: 'fa-book',
            points: 10
        },
        easy: {
            id: 'easy',
            name: 'Easy',
            description: 'Guided labs with 1-2 steps',
            color: '#22c55e',
            icon: 'fa-seedling',
            points: 25
        },
        medium: {
            id: 'medium',
            name: 'Medium',
            description: 'Multiple tools, chaining vulnerabilities',
            color: '#f59e0b',
            icon: 'fa-fire',
            points: 50
        },
        hard: {
            id: 'hard',
            name: 'Hard',
            description: 'Black box scenarios, no hints',
            color: '#ef4444',
            icon: 'fa-skull',
            points: 100
        },
        advanced: {
            id: 'advanced',
            name: 'Advanced',
            description: 'Binary exploitation, kernel exploits',
            color: '#a855f7',
            icon: 'fa-crown',
            points: 200
        }
    },

    // ==================== CATEGORIES ====================
    categories: {
        'web-security': {
            id: 'web-security',
            name: 'Web Security',
            description: 'OWASP Top 10, Injection, XSS, Web Exploitation',
            icon: 'fa-globe',
            color: '#3b82f6'
        },
        'digital-forensics': {
            id: 'digital-forensics',
            name: 'Digital Forensics',
            description: 'Memory, Disk, Network Forensics',
            icon: 'fa-magnifying-glass',
            color: '#06b6d4'
        },
        'cryptography': {
            id: 'cryptography',
            name: 'Cryptography',
            description: 'Ciphers, Hashing, PKI, Encryption',
            icon: 'fa-key',
            color: '#8b5cf6'
        },
        'reverse-engineering': {
            id: 'reverse-engineering',
            name: 'Reverse Engineering',
            description: 'Malware Analysis, Assembly, Binary Analysis',
            icon: 'fa-microscope',
            color: '#ec4899'
        },
        'network-security': {
            id: 'network-security',
            name: 'Network Security',
            description: 'Packet Analysis, Protocols, Network Attacks',
            icon: 'fa-network-wired',
            color: '#14b8a6'
        },
        'machines': {
            id: 'machines',
            name: 'Machines',
            description: 'Boot-to-Root challenges, Full system exploitation',
            icon: 'fa-server',
            color: '#f43f5e'
        },
        'linux': {
            id: 'linux',
            name: 'Linux',
            description: 'Linux fundamentals, commands, scripting',
            icon: 'fab fa-linux',
            color: '#fbbf24'
        },
        'windows': {
            id: 'windows',
            name: 'Windows',
            description: 'Windows security, Active Directory',
            icon: 'fab fa-windows',
            color: '#0ea5e9'
        }
    },

    // ==================== LEARNING PATH TYPES ====================
    pathTypes: {
        'pre-security': {
            id: 'pre-security',
            name: 'Pre-Security',
            description: 'Foundation for complete beginners',
            targetCareer: 'IT Support Specialist',
            avgSalary: '$45,000',
            icon: 'fa-graduation-cap',
            color: '#22c55e'
        },
        'jr-pentester': {
            id: 'jr-pentester',
            name: 'Jr Penetration Tester',
            description: 'Offensive security fundamentals',
            targetCareer: 'Junior Penetration Tester',
            avgSalary: '$65,000',
            icon: 'fa-user-secret',
            color: '#ef4444'
        },
        'cyber-defense': {
            id: 'cyber-defense',
            name: 'Cyber Defense',
            description: 'SOC Analyst preparation',
            targetCareer: 'SOC Analyst Level 1',
            avgSalary: '$55,000',
            icon: 'fa-shield-halved',
            color: '#3b82f6'
        },
        'web-hacking': {
            id: 'web-hacking',
            name: 'Web Hacking',
            description: 'Deep dive into web vulnerabilities',
            targetCareer: 'Web Application Pentester',
            avgSalary: '$75,000',
            icon: 'fa-bug',
            color: '#a855f7'
        }
    },

    // ==================== HELPER FUNCTIONS ====================

    getDifficultyBadge(difficultyId) {
        const diff = this.difficulties[difficultyId] || this.difficulties.easy;
        return `<span class="difficulty-badge" style="background: ${diff.color}; color: white; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;">
            <i class="fa-solid ${diff.icon}"></i> ${diff.name}
        </span>`;
    },

    getCategoryBadge(categoryId) {
        const cat = this.categories[categoryId] || this.categories['web-security'];
        return `<span class="category-badge" style="background: ${cat.color}20; color: ${cat.color}; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; border: 1px solid ${cat.color}40;">
            <i class="fa-solid ${cat.icon}"></i> ${cat.name}
        </span>`;
    },

    getPointsForDifficulty(difficultyId) {
        return this.difficulties[difficultyId]?.points || 25;
    },

    getAllDifficulties() {
        return Object.values(this.difficulties);
    },

    getAllCategories() {
        return Object.values(this.categories);
    },

    getAllPathTypes() {
        return Object.values(this.pathTypes);
    }
};

// Make globally available
window.PlatformTaxonomy = PlatformTaxonomy;
