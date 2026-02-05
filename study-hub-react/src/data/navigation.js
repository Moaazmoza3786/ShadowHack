import {
    LayoutDashboard,
    BookOpen,
    Terminal,
    Flag,
    Trophy,
    Settings,
    Shield,
    GraduationCap,
    Zap,
    History,
    Info,
    Youtube,
    Brain,
    Wrench,
    FileCode,
    Calendar,
    Gamepad2,
    Users,
    FileText,
    Lock,
    Bomb,
    Binoculars,
    UserCircle,
    Handshake,
    BadgeCheck,
    Bug,
    Search,
    Globe,
    Database,
    Microscope,
    Network,
    User,
    Activity,
    Radio,
    Library,
    Crown,
    Fingerprint,
    Bot,
    Code,
    Rocket,
    Key,
    Eye,
    Cpu,
    Newspaper
} from 'lucide-react';

export const navigationConfig = {
    // Direct links shown in navbar
    directLinks: [
        {
            id: 'dashboard',
            label: 'Dashboard',
            labelAr: 'لوحة التحكم',
            icon: LayoutDashboard,
            path: '/'
        },
        {
            id: 'second-brain',
            label: 'Second Brain',
            labelAr: 'العقل الثاني',
            icon: Brain,
            path: '/second-brain'
        }
    ],

    // Dropdown menus
    dropdowns: {
        tools: {
            label: 'Tools',
            labelAr: 'الأدوات',
            icon: Wrench,
            path: '/tools',
            layout: 'tabs',
            tabs: [
                {
                    id: 'offensive',
                    label: 'Offensive Labs',
                    labelAr: 'المختبرات الهجومية',
                    icon: Zap,
                    columns: [
                        {
                            title: 'Web & Cloud',
                            titleAr: 'الويب والسحابة',
                            items: [
                                {
                                    icon: Bug,
                                    label: 'Web Exploitation',
                                    labelAr: 'استغلال الويب',
                                    subtitle: 'XSS, SQLi & SSRF Lab',
                                    subtitleAr: 'مختبر الثغرات الأمنية',
                                    path: '/tools/web-exploitation'
                                },
                                {
                                    icon: Activity,
                                    label: 'JS Monitor Pro',
                                    labelAr: 'مراقب الجافا سكريبت الاحترافي',
                                    subtitle: 'DOM & Endpoint Analyzer',
                                    subtitleAr: 'مراقبة العميل المتقدمة',
                                    path: '/tools/js-monitor',
                                    badge: 'Pro'
                                },
                                {
                                    icon: Network,
                                    label: 'API Security',
                                    labelAr: 'أمن الواجهات البرمجية',
                                    subtitle: 'JWT & GraphQL testing',
                                    subtitleAr: 'اختبار JWT و GraphQL',
                                    path: '/tools/api-security',
                                    badge: 'Pro'
                                },
                                {
                                    icon: Globe,
                                    label: 'Cloud Security Pro',
                                    labelAr: 'أمن السحابة المحترف',
                                    subtitle: 'AWS/Azure Attack Vector',
                                    subtitleAr: 'هجمات السحابة المتقدمة',
                                    path: '/tools/cloud-security',
                                    badge: 'Pro'
                                }
                            ]
                        },
                        {
                            title: 'Intelligence',
                            titleAr: 'الاستخبارات',
                            items: [
                                {
                                    icon: Search,
                                    label: 'OSINT Pro',
                                    labelAr: 'مختبر أوسينت المحترف',
                                    subtitle: 'Open source intelligence',
                                    subtitleAr: 'جمع البيانات المفتوحة المتقدمة',
                                    path: '/tools/osint-lab',
                                    badge: 'Pro'
                                },
                                {
                                    icon: Fingerprint,
                                    label: 'Persona Pro',
                                    labelAr: 'مصنع الهوية الاحترافي',
                                    subtitle: 'Social Engineering Identities',
                                    subtitleAr: 'تقمص الشخصيات المتقدم',
                                    path: '/tools/persona-factory',
                                    badge: 'Pro'
                                },
                                {
                                    icon: Shield,
                                    label: 'PrivEsc Pro',
                                    labelAr: 'تصعيد الصلاحيات الاحترافي',
                                    subtitle: 'Win & Linux Mastery',
                                    subtitleAr: 'احتراف تصعيد الصلاحيات',
                                    path: '/tools/privesc-lab',
                                    badge: 'Pro'
                                },
                                {
                                    icon: Binoculars,
                                    label: 'Reconnaissance',
                                    labelAr: 'الاستطلاع',
                                    subtitle: 'Active & passive discovery',
                                    subtitleAr: 'الاكتشاف النشط والسلبي',
                                    path: '/tools/recon-lab'
                                },
                                {
                                    icon: Network,
                                    label: 'AD Attack Lab',
                                    labelAr: 'مختبر هجوم AD',
                                    subtitle: 'Active Directory simulation',
                                    subtitleAr: 'محاكاة أكتيف دايركتوري',
                                    path: '/tools/ad-attack-lab',
                                    badge: 'AI'
                                },
                                {
                                    icon: Newspaper,
                                    label: 'Cyber Intel Hub',
                                    labelAr: 'مركز الاستخبارات السيبرانية',
                                    subtitle: 'Live news & writeups',
                                    subtitleAr: 'أخبار ودروس مباشرة',
                                    path: '/cyber-intel',
                                    badge: 'Live'
                                },
                                {
                                    icon: Radio,
                                    label: 'CVE Radar',
                                    labelAr: 'رادار الثغرات',
                                    subtitle: 'Real-time vuln feed',
                                    subtitleAr: 'تغذية الثغرات المباشرة',
                                    path: '/tools/cve-radar'
                                },
                                {
                                    icon: Library,
                                    label: 'CVE Museum',
                                    labelAr: 'متحف الثغرات',
                                    subtitle: 'Historical archive',
                                    subtitleAr: 'الأرشيف التاريخي',
                                    path: '/tools/cve-museum'
                                },
                                {
                                    icon: FileText,
                                    label: 'Finding Reporter',
                                    labelAr: 'مبلغ الثغرات',
                                    subtitle: 'Professional reporting',
                                    subtitleAr: 'تقارير احترافية',
                                    path: '/tools/finding-reporter'
                                },
                                {
                                    icon: Network,
                                    label: 'C2 Command Ctr',
                                    labelAr: 'مركز القيادة C2',
                                    subtitle: 'Red Team Operations',
                                    subtitleAr: 'عمليات الفريق الأحمر',
                                    path: '/tools/c2-red-ops',
                                    badge: 'Sim'
                                }

                            ]
                        }
                    ]
                },
                {
                    id: 'defense',
                    label: 'Defense & Analysis',
                    labelAr: 'الدفاع والتحليل',
                    icon: Shield,
                    columns: [
                        {
                            title: 'Analysis',
                            titleAr: 'التحليل',
                            items: [
                                {
                                    icon: Microscope,
                                    label: 'Malware Sandbox',
                                    labelAr: 'مختبر الفيروسات',
                                    subtitle: 'Behavioral analysis engine',
                                    subtitleAr: 'محرك تحليل السلوك',
                                    path: '/tools/malware-sandbox',
                                    badge: 'Alpha'
                                },
                                {
                                    icon: Eye,
                                    label: 'Stego Analyst',
                                    labelAr: 'تحليل الإخفاء',
                                    subtitle: 'LSB & Metadata Tools',
                                    subtitleAr: 'أدوات تحليل الصور',
                                    path: '/tools/stego-lab',
                                    badge: 'New'
                                }
                            ]
                        },
                        {
                            title: 'Utilities',
                            titleAr: 'أدوات مساعدة',
                            items: [
                                {
                                    icon: Bomb,
                                    label: 'Payload Gen',
                                    labelAr: 'مولد البايلود',
                                    subtitle: 'Shell factory & payloads',
                                    subtitleAr: 'مصنع الشلات والبايلودات',
                                    path: '/tools/payload-gen'
                                },
                                {
                                    icon: Lock,
                                    label: 'Encoder Tool',
                                    labelAr: 'أداة التشفير',
                                    subtitle: 'Multi-format encoding',
                                    subtitleAr: 'ترميز وفك تنسيقات متنوعة',
                                    path: '/tools/encoder'
                                },
                                {
                                    icon: Key,
                                    label: 'Password Cracker',
                                    labelAr: 'كاسر كلمات المرور',
                                    subtitle: 'Hash ID & Wordlists',
                                    subtitleAr: 'تحليل الهاش وقوائم الكلمات',
                                    path: '/tools/password-cracker',
                                    badge: 'Pro'
                                },
                                {
                                    icon: Cpu,
                                    label: 'Crypto Forge',
                                    labelAr: 'مختبر التشفير',
                                    subtitle: 'Ciphers & Hashing',
                                    subtitleAr: 'تشفير وفك تشفير',
                                    path: '/tools/crypto-lab'
                                }
                            ]
                        }
                    ]
                },
                {
                    id: 'management',
                    label: 'Operations',
                    labelAr: 'العمليات',
                    icon: LayoutDashboard,
                    columns: [
                        {
                            title: 'Management',
                            titleAr: 'الإدارة',
                            items: [
                                {
                                    icon: Rocket,
                                    label: 'DevSecOps Architect',
                                    labelAr: 'مهندس DevSecOps',
                                    subtitle: 'Secure Pipeline Generator',
                                    subtitleAr: 'منشئ خطوط الأنابيب الآمنة',
                                    path: '/tools/devsecops-lab',
                                    badge: 'New'
                                },
                                {
                                    icon: Users,
                                    label: 'Target Manager',
                                    labelAr: 'مدير الأهداف',
                                    subtitle: 'Asset tracking & scope',
                                    subtitleAr: 'تتبع الأصول والنطاق',
                                    path: '/tools/target-manager'
                                },
                                {
                                    icon: Calendar,
                                    label: 'Campaigns',
                                    labelAr: 'الحملات',
                                    subtitle: 'Engagement management',
                                    subtitleAr: 'إدارة المهام',
                                    path: '/tools/campaign-manager'
                                },
                                {
                                    icon: FileText,
                                    label: 'Report Builder',
                                    labelAr: 'منشئ التقارير',
                                    subtitle: 'Professional reporting',
                                    subtitleAr: 'تقارير احترافية',
                                    path: '/tools/report-builder'
                                }
                            ]
                        },
                        {
                            title: 'Reference',
                            titleAr: 'المراجع',
                            items: [
                                {
                                    icon: FileCode,
                                    label: 'Cheatsheets',
                                    labelAr: 'أوراق الغش',
                                    subtitle: 'Quick command reference',
                                    subtitleAr: 'مرجع سريع للأوامر',
                                    path: '/tools/cheatsheets'
                                },
                                {
                                    icon: Code,
                                    label: 'Command Reference',
                                    labelAr: 'مرجع الأوامر',
                                    subtitle: '200+ Commands & Syntax',
                                    subtitleAr: 'أكثر من 200 أمر',
                                    path: '/tools/command-ref'
                                },
                                {
                                    icon: Shield,
                                    label: 'MITRE ATT&CK',
                                    labelAr: 'مصفوفة MITRE',
                                    subtitle: 'Tactics & Techniques',
                                    subtitleAr: 'تكتيكات وتقنيات',
                                    path: '/tools/mitre-attack'
                                }
                            ]
                        }
                    ]
                }
            ]
        },

        learn: {
            label: 'Learn',
            labelAr: 'تعلم',
            icon: GraduationCap,
            columns: [
                {
                    title: 'Academy',
                    titleAr: 'الأكاديمية',
                    items: [
                        {
                            icon: BookOpen,
                            label: 'All Courses',
                            labelAr: 'جميع الدورات',
                            subtitle: 'Structured video courses',
                            subtitleAr: 'دورات فيديو منظمة',
                            path: '/courses'
                        },
                        {
                            icon: Users,
                            label: 'Career Hub',
                            labelAr: 'مركز المهن',
                            subtitle: 'Path to professional roles',
                            subtitleAr: 'الطريق للأدوار المهنية',
                            path: '/career-hub'
                        },
                        {
                            icon: Youtube,
                            label: 'YouTube Hub',
                            labelAr: 'منصة يوتيوب',
                            subtitle: 'Free community education',
                            subtitleAr: 'تعليم مجتمعي مجاني',
                            path: '/youtube-hub',
                            badge: 'Free'
                        }
                    ]
                },
                {
                    title: 'Specializations',
                    titleAr: 'التخصصات',
                    items: [
                        {
                            icon: Info,
                            label: 'ShadowHack Specs',
                            labelAr: 'تخصصات ShadowHack',
                            subtitle: 'System infrastructure details',
                            subtitleAr: 'تفاصيل البنية التحتية',
                            path: '/specs'
                        },
                        {
                            icon: History,
                            label: 'Legacy Tracks',
                            labelAr: 'المسارات الكلاسيكية',
                            subtitle: 'Archived learning paths',
                            subtitleAr: 'مسارات تعلم مؤرشفة',
                            path: '/legacy-tracks'
                        }
                    ]
                }
            ]
        },

        practice: {
            label: 'Practice',
            labelAr: 'تدريب',
            icon: Gamepad2,
            columns: [
                {
                    title: 'Challenges',
                    titleAr: 'التحديات',
                    items: [
                        {
                            icon: Flag,
                            label: 'CTF Arena',
                            labelAr: 'ساحة CTF',
                            subtitle: 'Ranked capture the flag tags',
                            subtitleAr: 'تحديات CTF مصنفة',
                            path: '/ctf'
                        },
                        {
                            icon: Calendar,
                            label: 'Daily Challenge',
                            labelAr: 'تحدي اليوم',
                            subtitle: 'Fresh missions every 24h',
                            subtitleAr: 'مهام جديدة كل 24 ساعة',
                            path: '/ctf/daily',
                            badge: 'New'
                        }
                    ]
                },
                {
                    title: 'Simulators',
                    titleAr: 'المحاكاة',
                    items: [
                        {
                            icon: Shield,
                            label: 'OWASP Range',
                            labelAr: 'مختبر OWASP',
                            subtitle: 'Interactive AppSec training',
                            subtitleAr: 'تدريب AppSec تفاعلي',
                            path: '/owasp-range',
                            badge: 'Lab'
                        },
                        {
                            icon: Terminal,
                            label: 'Labs Dashboard',
                            labelAr: 'لوحة المختبرات',
                            subtitle: 'Deployable practice machines',
                            subtitleAr: 'ماكينات تدريب قابلة للنشر',
                            path: '/labs'
                        },
                        {
                            icon: Zap,
                            label: 'Advanced Campaigns',
                            labelAr: 'حملات متقدمة',
                            subtitle: 'Complex red team scenarios',
                            subtitleAr: 'سيناريوهات فريق أحمر معقدة',
                            path: '/labs/campaigns'
                        }
                    ]
                },
            ]
        },

        platform: {
            label: 'Network',
            labelAr: 'الشبكة',
            icon: Users,
            columns: [
                {
                    title: 'Community',
                    titleAr: 'المجتمع',
                    items: [
                        {
                            icon: UserCircle,
                            label: 'About ShadowHack',
                            labelAr: 'عن ShadowHack',
                            subtitle: 'Our mission and vision',
                            subtitleAr: 'مهمتنا ورؤيتنا',
                            path: '/about'
                        },
                        {
                            icon: Handshake,
                            label: 'Partners',
                            labelAr: 'الشركاء',
                            subtitle: 'Official collaboration',
                            subtitleAr: 'التعاون الرسمي',
                            path: '/partners'
                        }
                    ]
                },
                {
                    title: 'Certification',
                    titleAr: 'الشهادات',
                    items: [
                        {
                            icon: BadgeCheck,
                            label: 'Verify Certificate',
                            labelAr: 'التحقق من الشهادة',
                            subtitle: 'Validate your achievement',
                            subtitleAr: 'تحقق من إنجازك',
                            path: '/verify'
                        }
                    ]
                }
            ]
        }
    },

    // Right side items
    rightItems: [
        {
            id: 'achievements',
            label: 'Achievements',
            labelAr: 'الإنجازات',
            icon: Trophy,
            path: '/achievements'
        },
        {
            id: 'settings',
            label: 'Settings',
            labelAr: 'الإعدادات',
            icon: Settings,
            path: '/settings'
        }
    ]
};
