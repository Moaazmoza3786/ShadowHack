/* ============================================================
   SHADOW OS - WORLD DATABASE 🌍
   The "Matrix" of the simulation. Contains all fake companies,
   NPCs, dark web items, and stock market data.
   ============================================================ */

const SHADOW_DB = {
    // --- GLOBAL ECONOMY & STOCKS ---
    STOCKS: [
        { sym: 'NEX', name: 'Nexus Corp', price: 1450.20, vol: 'High', type: 'Tech' },
        { sym: 'GLD', name: 'Global Dynamics', price: 890.50, vol: 'Med', type: 'Defense' },
        { sym: 'SCB', name: 'SecureBank', price: 45.10, vol: 'Low', type: 'Finance' },
        { sym: 'OMN', name: 'OmniBiotech', price: 320.75, vol: 'High', type: 'Pharma' },
        { sym: 'AEO', name: 'AeroSpace Ind', price: 2100.00, vol: 'Med', type: 'Aerospace' }
    ],

    // --- TARGET COMPANIES (REALISTIC STACKS) ---
    COMPANIES: {
        'nexus': {
            name: 'Nexus Corp',
            domain: 'nexus-corp.com',
            desc: 'Global leader in predictive policing algorithms and biometrics.',
            securityLevel: 5,
            techStack: ['Kubernetes', 'AWS Lambda', 'SentinelOne EDR'],
            employees: ['ceo', 'cto', 'admin', 'dev'],
            servers: ['10.50.1.5 (Gateway)', '10.50.1.10 (Auth)', '192.168.1.100 (Intranet)']
        },
        'global': {
            name: 'Global Dynamics',
            domain: 'global-dyn.com',
            desc: 'Defense contractor specializing in autonomous loitering munitions.',
            securityLevel: 4,
            techStack: ['Azure AD', 'Cisco Firepower', 'Splunk'],
            employees: ['sec_chief', 'engineer'],
            servers: ['172.16.0.5 (VPN)', '172.16.0.20 (GitLab)']
        }
    },

    // --- DARK WEB MARKETPLACE (HIGH FIDELITY) ---
    BLACK_MARKET: [
        { id: 'cve_2024_2111', name: '0-Day: CVE-2024-2111', price: 15000, desc: 'Oracle VirtualBox Escalate to Host (RCE). Unpatched.', type: 'exploit' },
        { id: 'dump_comb', name: 'Comb2.1 Breach Data', price: 2500, desc: '3.2 Billion unique pairs (Email:Pass). Indexed.', type: 'data' },
        { id: 'hw_flipper', name: 'Flipper Zero (Modded)', price: 450, desc: 'Hardware text/sub-ghz transceiver with custom firmware.', type: 'hardware' },
        { id: 'hosting_bp', name: 'Bulletproof HOST (Seychelles)', price: 600, desc: 'DMCA ignored. No logs. 10Gbps uplink.', type: 'service' },
        { id: 'kit_phish', name: 'Evilginx3 config pack', price: 1200, desc: 'Bypass 2FA with reverse proxy templates for M365/Google.', type: 'soft' },
        { id: 'access_corp', name: 'Citrix Access (Fortune 500)', price: 8000, desc: 'Valid session cookies for logic-corp.com.', type: 'access' }
    ],

    // --- NPC PROFILES (OSINT TARGETS) ---
    NPCS: {
        'susan_vance': {
            id: 'susan_vance',
            name: 'Susan Vance',
            role: 'HR Manager',
            company: 'Corp-X',
            email: 'svance@corp-x.local',
            details: {
                stress: 'high',
                pet: 'Buster',
                vacation: 'Hawaii'
            },
            credentials: {
                username: 'svance',
                password: 'Buster123!'
            },
            social: {
                linkedUp: {
                    handle: 'susan-vance',
                    posts: [
                        { date: '1d ago', text: 'Excited to join Corp-X as HR Manager! Looking forward to building great teams. #HR #CorpX' },
                        { date: '2y ago', text: 'Goodbye massive corporation, hello new adventures! #CareerChange' }
                    ],
                    skills: ['Talent Acquisition', 'Crisis Management', 'Payroll Systems']
                },
                faceSpace: {
                    handle: 'susan.v88',
                    photos: [
                        { caption: 'Buster loves the park! 🐕', img: 'dog_park.jpg', comments: ['Cute!', 'Is that Golden Gate Park?'] },
                        { caption: 'Dreaming of Hawaii... 🌺', img: 'vacation_dream.jpg' }
                    ]
                }
            }
        },
        'john_doe': {
            id: 'john_doe',
            name: 'John Doe',
            role: 'Senior DevOps @ Nexus Corp',
            email: 'j.doe@nexus-corp.com',
            passHash: '7f9a8b...', // 'password123'
            discProfile: 'C', // Conscientious (Needs details)
            interests: ['Golf', 'Startrek', 'Python'],
            socialPosts: [
                { platform: 'LinkedUp', date: '2d ago', text: 'Excited to deploy the new Kubernetes cluster at Nexus! #K8s #DevOps' },
                { platform: 'FaceSpace', date: '5d ago', text: 'Happy 5th Birthday to my dog, Buster! 🐕' }
            ],
            secrets: {
                pet: 'Buster',
                dob: '1985-04-12'
            },
            voiceSample: 'sample_male_tech.mp3'
        },
        'sarah_connor': {
            id: 'sarah_connor',
            name: 'Sarah Connor',
            role: 'Head of Security @ Global Dynamics',
            email: 's.connor@global-dyn.com',
            discProfile: 'D', // Dominant (Needs directness)
            interests: ['Guns', 'Fitness', 'Privacy'],
            socialPosts: [
                { platform: 'LinkedUp', date: '1d ago', text: 'Zero trust is not a buzzword. It is a necessity. #CyberSec' },
                { platform: 'Twitter', date: '3h ago', text: 'Another day, another attempted breach. Amateurs.' }
            ],
            secrets: {
                pin: '1984'
            },
            voiceSample: 'sample_female_strict.mp3'
        }
    },

    // --- NEWS HEADLINES (DYNAMIC) ---
    NEWS_TEMPLATES: {
        hack: [
            "BREAKING: {TARGET} Stock Plummets After Massive Data Breach!",
            "Cyber Terrorists Claim Responsibility for {TARGET} Outage.",
            "Whistleblower Leaks Internal Documents from {TARGET}."
        ],
        defense: [
            "{TARGET} Announces New AI-Powered Security Grid.",
            "Market Rally: {TARGET} Shares Soar on Defense Contract."
        ]
    }
};

window.SHADOW_DB = SHADOW_DB;
