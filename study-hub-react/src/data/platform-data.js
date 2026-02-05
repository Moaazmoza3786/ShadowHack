export const PLATFORM_DATA = {
    domains: [
        {
            id: 'red-team',
            name: 'Red Team',
            nameAr: 'الفريق الأحمر',
            subtitle: 'Offensive Security',
            description: 'Master offensive security techniques including penetration testing, vulnerability exploitation, and advanced attack methodologies.',
            icon: 'Crosshairs',
            color: '#ef4444',
            paths: ['web-pentesting', 'network-hacking', 'exploit-dev', 'mobile-hacking', 'wireless-hacking', 'social-engineering']
        },
        {
            id: 'blue-team',
            name: 'Blue Team',
            nameAr: 'الفريق الأزرق',
            subtitle: 'Defensive Security',
            description: 'Learn defensive security operations including SOC analysis, incident response, digital forensics, and threat hunting.',
            icon: 'Shield',
            color: '#3b82f6',
            paths: ['soc-analyst', 'digital-forensics', 'malware-analysis', 'threat-hunting', 'incident-response']
        }
    ],
    paths: {
        'web-pentesting': {
            id: 'web-pentesting',
            domainId: 'red-team',
            name: 'Web Penetration Testing',
            nameAr: 'اختبار اختراق الويب',
            description: 'Master web application vulnerabilities from basics to advanced exploitation including OWASP Top 10 and beyond.',
            icon: 'Globe',
            difficulty: 'intermediate',
            estimatedHours: 40
        },
        'soc-analyst': {
            id: 'soc-analyst',
            domainId: 'blue-team',
            name: 'SOC Analyst',
            nameAr: 'محلل SOC',
            description: 'Security Operations Center analysis, monitoring, SIEM operations, and incident response.',
            icon: 'Eye',
            difficulty: 'beginner',
            estimatedHours: 35
        }
    }
};
