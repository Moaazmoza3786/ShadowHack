/* learn-section-v6.js */
/* Professional Learn Section Implementation V6.0 - HackingHub Replica */
/* Updates for Phase 2: Path > Course > Module > Room Hierarchy */

/* --- Legacy Courses Bridge (courses-data.js -> UnifiedLearningData) --- */
function escapeHTMLV6(str = '') {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function normalizeDifficulty(level = 'Intermediate') {
    const l = String(level).toLowerCase();
    if (l.includes('begin')) return 'Beginner';
    if (l.includes('adv')) return 'Advanced';
    return 'Intermediate';
}

function buildLessonTaskV6(lesson) {
    const title = lesson.titleAr || lesson.title || 'Lesson';
    const duration = lesson.duration ? `<p class="text-muted small mb-2">${lesson.duration}</p>` : '';
    const body = lesson.content ? `<pre class="bg-dark text-white p-3 rounded-3">${escapeHTMLV6(lesson.content)}</pre>` : '<div class="text-muted">لا يوجد محتوى بعد</div>';
    return {
        title,
        type: lesson.type || 'lesson',
        content: `<h3 class="text-white">${title}</h3>${duration}${body}`
    };
}

function buildQuizTaskV6(quiz) {
    if (!quiz || !quiz.questions || !quiz.questions.length) return null;
    const questionsHTML = quiz.questions.map(q => `
        <div class="mb-3">
            <div class="fw-bold text-white">${q.question}</div>
            <div class="text-muted small">${Array.isArray(q.options) ? q.options.map((o, i) => `${i + 1}. ${escapeHTMLV6(o)}`).join('<br>') : ''}</div>
            ${q.explanation ? `<div class="alert alert-info mt-2 p-2">${escapeHTMLV6(q.explanation)}</div>` : ''}
        </div>
    `).join('');

    return {
        title: quiz.title || 'Quiz',
        type: 'quiz',
        content: `<div class="quiz-card-lesson p-3 glass-box">${questionsHTML}</div>`
    };
}

function integrateLegacyCoursesIntoUnifiedData() {
    const uData = window.UnifiedLearningData || (window.UnifiedLearningData = { paths: [], modules: [] });

    // Ensure helpers exist
    if (!uData.getCourseById) uData.getCourseById = function (courseId) { return (this.courses || []).find(c => c.id === courseId); };
    if (!uData.getCourseModules) uData.getCourseModules = function (courseId) { const c = this.getCourseById(courseId); return c ? (c.modules || c.rooms || []) : []; };
    if (!uData.getModuleById) uData.getModuleById = function (moduleId) { return (this.modules || []).find(m => m.id === moduleId); };

    const legacyCourses = Array.isArray(window.courses) ? window.courses : [];
    uData.courses = uData.courses || [];
    const existingCourseIds = new Set(uData.courses.map(c => c.id));

    legacyCourses.forEach(course => {
        if (existingCourseIds.has(course.id)) return;

        const mappedModules = (course.modules || []).map(mod => {
            const moduleId = `${course.id}-${mod.id}`;
            const lessonTasks = (mod.lessons || []).map(buildLessonTaskV6);
            const quizTask = buildQuizTaskV6(mod.quiz);
            if (quizTask) lessonTasks.push(quizTask);

            const moduleObj = {
                id: moduleId,
                title: mod.titleAr || mod.title,
                description: mod.duration ? `${mod.duration}` : mod.title,
                difficulty: normalizeDifficulty(course.level),
                icon: 'fa-layer-group',
                tasks: lessonTasks
            };
            return moduleObj;
        });

        const normalizedCourse = {
            id: course.id,
            title: course.titleAr || course.title,
            description: course.description || course.descriptionEn || '',
            difficulty: normalizeDifficulty(course.level),
            icon: 'fa-graduation-cap',
            modules: mappedModules
        };

        uData.courses.push(normalizedCourse);

        // Register modules globally for module viewer
        uData.modules = uData.modules || [];
        const existingModuleIds = new Set(uData.modules.map(m => m.id));
        mappedModules.forEach(m => { if (!existingModuleIds.has(m.id)) uData.modules.push(m); });
    });

    return uData;
}

/* --- Data Aggregation Helper (V6) --- */
function getIntegratedLearnDataV6() {
    const uData = integrateLegacyCoursesIntoUnifiedData();

    // 1. Courses (New Layer - Source of Truth for Content)
    // We map directly from UnifiedLearningData.courses
    const courses = (uData.courses || []).map(c => ({
        id: c.id,
        title: c.title,
        description: c.description,
        difficulty: c.difficulty || 'Intermediate',
        icon: c.icon || 'fa-graduation-cap',
        xp: 1000, // Placeholder calculation
        hours: Math.floor(Math.random() * 20) + 10, // Mock hours if missing
        rooms: (c.modules || []).length * 3, // Approx rooms
        modules: c.modules || []
    }));

    // 2. Paths (Now composed of COURSES)
    const paths = (uData.paths || []).map(p => {
        // Resolve courses for this path
        const pathCourses = uData.getPathCourses ? uData.getPathCourses(p.id) : [];

        return {
            id: p.id,
            title: p.title,
            type: 'Career Path',
            difficulty: 'Intermediate', // Aggregate later
            status: 'Free',
            xp: pathCourses.length * 1000,
            icon: p.icon || 'fa-map-signs',
            color: p.color || '#8273DD',
            description: p.description,
            hours: p.estimatedHours || 50,
            coursesCount: pathCourses.length, // Valid metric
            rooms: 0 // Will need recursive calc
        };
    });

    // 3. Modules (Legacy support + direct listing)
    const modules = (uData.modules || []).map(m => ({
        id: m.id,
        title: m.title,
        type: 'Module',
        difficulty: 'Easy',
        status: 'Not Started',
        xp: 500,
        icon: m.icon || 'fa-cube',
        color: '#3b82f6',
        description: m.description,
        rooms: m.rooms || []
    }));

    // Apply Smart Icons (DISABLED - Using professional Font Icons as requested)
    // paths.forEach(p => { if (!p.icon || p.icon.startsWith('fa-')) p.icon = getSmartIconV6(p.title, 'path'); });
    // courses.forEach(c => { if (!c.icon || c.icon.startsWith('fa-')) c.icon = getSmartIconV6(c.title); });
    // modules.forEach(m => { if (!m.icon || m.icon.startsWith('fa-')) m.icon = getSmartIconV6(m.title, 'module'); });

    return { paths, courses, modules };
}

function getSmartIconV6(title, type = '') {
    if (!title) return 'assets/images/3d-icons/icon_security_3d_1765817313667.png';
    const t = String(title).toLowerCase() + ' ' + String(type).toLowerCase();
    const p = 'assets/images/3d-icons/';
    if (t.includes('pre security') || t.includes('intro')) return p + 'icon_security_3d_1765817313667.png';
    if (t.includes('web') || t.includes('bug bounty')) return p + 'icon_web_3d_1765817117593.png';
    if (t.includes('linux')) return p + 'icon_linux_3d_1765817009790.png';
    if (t.includes('network')) return p + 'icon_network_3d_1765817211308.png';
    if (t.includes('soc')) return p + 'icon_soc_level1_3d_1765924843102.png';
    if (t.includes('pentest') || t.includes('e-jpt') || t.includes('junior')) return p + 'icon_offensive_pentest_3d_1765924906299.png';
    if (t.includes('red team') || t.includes('offensive')) return p + 'icon_access_3d_1765819070867.png';
    if (t.includes('malware')) return p + 'icon_malware_3d_1765923577789.png';
    if (t.includes('python') || t.includes('scripting')) return p + 'icon_scripting_3d_1765819420953.png';
    if (t.includes('active directory')) return p + 'icon_ad_forest_3d_1765819581743.png';
    if (type === 'path') return p + 'icon_learning_path_3d_1765922272083.png';
    return p + 'icon_security_3d_1765817313667.png';
}

function getLearnStylesV6() {
    return `
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&family=Orbitron:wght@400;500;600;700;900&display=swap');

        :root {
            --hh-bg: #0d0b14;
            --hh-card-bg: rgba(255,255,255,0.02);
            --hh-card-border: rgba(255, 255, 255, 0.08);
            --hh-purple: #8273DD;
            --hh-text-white: #ffffff;
            --hh-text-muted: #9CA3AF;
            --font-display: 'Orbitron', 'Cairo', sans-serif;
        }
        
        /* Force Orbitron/Cairo for headings to match Home Page "Featured Paths" font */
        h1, h2, h3, h4, .v6-title, .v6-badge {
            font-family: var(--font-display) !important;
        }

        .learn-container { 
            font-family: 'Outfit', 'Cairo', sans-serif !important; 
            background: var(--hh-bg); 
            min-height: 100vh; 
            color: var(--hh-text-white); 
            padding-bottom: 80px; 
        }

        /* --- Unified Card Design (From Home Page "Featured Paths") --- */
        .path-card-unified { 
            background: rgba(255,255,255,0.02); 
            border: 1px solid rgba(255,255,255,0.08); 
            border-radius: 20px; 
            padding: 30px;
            display: flex; 
            gap: 20px; 
            align-items: flex-start; 
            cursor: pointer; 
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            min-height: 200px;
            position: relative;
            overflow: hidden;
        }
        .path-card-unified:hover { 
            border-color: rgba(255,255,255,0.2); 
            background: rgba(255,255,255,0.04); 
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        
        .path-icon-wrapper { 
            width: 60px; 
            height: 60px; 
            border-radius: 16px; 
            border: 2px solid; 
            border-color: var(--card-color, #8273DD);
            display: flex; 
            align-items: center; 
            justify-content: center;
            background: rgba(0,0,0,0.3); 
            flex-shrink: 0;
            transition: transform 0.3s;
        }
        .path-card-unified:hover .path-icon-wrapper {
            transform: scale(1.1) rotate(5deg);
        }

        .path-icon { font-size: 24px; color: var(--card-color, #8273DD); }
        
        .path-info { flex-grow: 1; }
        .path-info h3 { margin: 0 0 10px 0; color: #fff; font-size: 1.4rem; font-weight: 700; line-height: 1.2; }
        .path-info p { margin: 0 0 20px 0; color: #9ca3af; font-size: 0.95rem; line-height: 1.6; }
        
        .path-progress-container { width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; margin-bottom: 15px; overflow: hidden; }
        .path-progress-bar { height: 100%; box-shadow: 0 0 10px; background: var(--card-color, #8273DD); }
        
        .path-status { font-size: 0.85rem; font-weight: 600; display: flex; align-items: center; gap: 5px; color: var(--card-color, #8273DD); text-transform: uppercase; letter-spacing: 1px; }
        .glass-box { background: rgba(255,255,255,0.03); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }
        .hover-visible { opacity: 0; transition: opacity 0.3s ease; }
        .quiz-card-lesson:hover .hover-visible { opacity: 1; }
        
        .code-header { background: #1a1a1a; padding: 8px 15px; font-size: 0.75rem; font-weight: bold; border-radius: 6px 6px 0 0; border: 1px solid var(--hh-border); border-bottom: none; color: #888; letter-spacing: 1px; }
        .hover-white:hover { color: white !important; }
        .animate-pulse { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
        
        /* Grid Layout */
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 30px; padding: 24px 0; }
        
        .learn-hero-v6 { background: linear-gradient(180deg, rgba(130, 115, 221, 0.05) 0%, transparent 100%); border-bottom: 1px solid var(--hh-card-border); padding: 60px 0; margin-bottom: 40px; text-align: center; }
        
        .section-divider {
            display: flex; align-items: center; gap: 20px; margin: 60px 0 40px;
        }
        .section-divider h2 { margin: 0; white-space: nowrap; font-size: 1.8rem; color: #fff; }
        .section-divider .line { height: 1px; background: rgba(255,255,255,0.1); width: 100%; }

        .fade-in { animation: fadeIn 0.4s ease-out forwards; opacity: 0; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        /* --- Path Details Specifics --- */
        .path-header-v6 { 
            background: linear-gradient(135deg, rgba(130, 115, 221, 0.1) 0%, rgba(130, 115, 221, 0.02) 100%);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 24px;
            padding: 50px;
            margin-bottom: 40px;
            display: flex;
            gap: 40px;
            align-items: center;
        }
        .path-header-icon {
            width: 140px; height: 140px;
            background: rgba(0,0,0,0.4);
            border: 3px solid var(--hh-purple);
            border-radius: 30px;
            display: flex; align-items: center; justify-content: center;
            font-size: 60px; color: var(--hh-purple);
            box-shadow: 0 0 30px rgba(130, 115, 221, 0.3);
        }
        
        .timeline-container { position: relative; padding-left: 50px; }
        .timeline-container::before {
            content: ''; position: absolute; left: 24px; top: 0; bottom: 0;
            width: 2px; background: rgba(255,255,255,0.1);
        }
        
        .timeline-item {
            position: relative; margin-bottom: 40px;
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 16px; 
            padding: 24px;
            transition: all 0.3s;
            cursor: pointer;
        }
        .timeline-item:hover { background: rgba(255,255,255,0.04); border-color: rgba(255,255,255,0.15); transform: translateX(10px); }
        .timeline-item::before {
            content: ''; position: absolute; left: -34px; top: 32px;
            width: 16px; height: 16px; border-radius: 50%;
            background: #2a2735; border: 3px solid rgba(255,255,255,0.2);
            z-index: 2;
        }
        .timeline-item.completed::before { border-color: #22c55e; background: #22c55e; }
        .timeline-item.locked { opacity: 0.6; cursor: not-allowed; }
        .timeline-item.locked::before { border-color: #4b5563; }
        
        .cert-preview {
            background: rgba(0,0,0,0.3); border: 1px dashed rgba(255,255,255,0.1);
            border-radius: 20px; padding: 40px; text-align: center;
            position: relative; overflow: hidden;
        }
        .cert-img-blur { width: 100%; filter: blur(10px) brightness(0.5); opacity: 0.5; border-radius: 10px; }
        .cert-overlay { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 100%; }

        /* --- Learning Interface (Dashboard) --- */
        .learn-interface { display: flex; height: 100vh; background: #08070d; overflow: hidden; }
        .sidebar-tasks { 
            width: 320px; background: #0d0b14; border-right: 1px solid rgba(255,255,255,0.05);
            display: flex; flex-direction: column;
        }
        .task-list { overflow-y: auto; flex-grow: 1; padding: 15px; }
        .task-nav-item {
            padding: 15px; border-radius: 12px; margin-bottom: 8px; cursor: pointer;
            border: 1px solid transparent; transition: all 0.2s;
            display: flex; align-items: center; gap: 12px;
        }
        .task-nav-item:hover { background: rgba(255,255,255,0.03); }
        .task-nav-item.active { background: rgba(130, 115, 221, 0.1); border-color: rgba(130, 115, 221, 0.2); }
        .task-num { width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 800; background: rgba(255,255,255,0.05); color: #9ca3af; }
        .task-nav-item.active .task-num { background: var(--hh-purple); color: #fff; }
        
        .main-learning-content { flex-grow: 1; overflow-y: auto; display: flex; flex-direction: column; position: relative; }
        .content-header { padding: 30px 40px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .content-body { padding: 40px; flex-grow: 1; max-width: 900px; margin: 0 auto; width: 100%; }
        
        .lab-footer { 
            background: #0d0b14; border-top: 1px solid rgba(255,255,255,0.05); padding: 30px 40px;
        }
        .question-box {
            background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px; padding: 20px;
        }
        .code-box { background: #1a1625; padding: 20px; border-radius: 12px; font-family: monospace; border-left: 4px solid var(--hh-purple); margin: 20px 0; }
        
        /* --- Premium Path Card (V6) --- */
        .path-card-premium {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 25px;
            position: relative;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            display: flex;
            flex-direction: column;
            height: 100%;
            cursor: pointer;
        }
        
        .path-card-premium::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            border-radius: 20px;
            padding: 2px;
            background: linear-gradient(135deg, rgba(255,255,255,0.1), transparent 50%);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            opacity: 0.5;
            transition: opacity 0.4s;
        }

        .path-card-premium:hover {
            transform: translateY(-8px);
            background: rgba(255, 255, 255, 0.05);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(130, 115, 221, 0.2);
            border-color: var(--hh-purple);
        }

        .path-card-premium:hover::before {
            opacity: 1;
            background: linear-gradient(135deg, var(--hh-purple), transparent 60%);
        }

        .path-card-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }

        .path-icon-lg {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            background: rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: var(--hh-purple);
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.4s;
        }

        .path-card-premium:hover .path-icon-lg {
            transform: scale(1.1) rotate(5deg);
            border-color: var(--hh-purple);
            box-shadow: 0 0 15px rgba(130, 115, 221, 0.3);
        }

        .path-stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: auto;
            border-top: 1px solid rgba(255,255,255,0.1);
            padding-top: 15px;
        }

        .path-stat {
            text-align: center;
        }

        .path-stat-val {
            font-size: 0.9rem;
            font-weight: 700;
            color: #fff;
            display: block;
        }

        .path-stat-label {
            font-size: 0.7rem;
            color: #9ca3af;
            text-transform: uppercase;
        }
        
        .path-action-btn {
            margin-top: 15px;
            width: 100%;
            background: linear-gradient(90deg, var(--hh-purple), #6b5bbf);
            color: white;
            border: none;
            padding: 10px;
            border-radius: 8px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
            opacity: 0;
            transform: translateY(10px);
            transition: all 0.3s;
        }

        .path-card-premium:hover .path-action-btn {
            opacity: 1;
            transform: translateY(0);
        }

        /* --- Premium Course Card --- */
        .course-card-premium {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
            cursor: pointer;
            height: 100%;
            display: flex;
            flex-direction: column;
        }

        .course-card-premium:hover {
            transform: translateY(-5px);
            background: rgba(255, 255, 255, 0.04);
            border-color: var(--card-color, #4facfe);
            box-shadow: 0 10px 25px rgba(0,0,0,0.3), 0 0 15px rgba(var(--card-rgb), 0.2);
        }
        
        .course-card-premium .course-icon-wrapper {
            width: 45px; height: 45px;
            border-radius: 10px;
            background: rgba(var(--card-rgb), 0.15);
            color: var(--card-color);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.2rem;
            margin-bottom: 15px;
            border: 1px solid rgba(var(--card-rgb), 0.3);
        }

        /* --- Premium Module Card --- */
        .module-card-premium {
            background: rgba(20, 20, 25, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-left: 3px solid var(--module-color, #6c757d);
            border-radius: 12px;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .module-card-premium:hover {
            background: rgba(255, 255, 255, 0.05);
            transform: translateX(5px);
            border-left-width: 5px;
        }
        
        .module-icon-sm {
            width: 36px; height: 36px;
            border-radius: 8px;
            background: rgba(0,0,0,0.3);
            display: flex; align-items: center; justify-content: center;
            color: var(--module-color);
            font-size: 1rem;
        }
    </style>
    `;
}

/* --- Render Functions --- */

// 1. Path Card (Click -> pagePathRoadmapV6)
function renderPathCardV6(path) {
    const iconSrc = getSmartIconV6(path.title, 'path');
    const courseCount = path.coursesCount || (Array.isArray(path.courses) ? path.courses.length : 0);
    const difficultyColor = path.difficulty === 'Beginner' ? '#22c55e' : path.difficulty === 'Advanced' ? '#ef4444' : '#eab308';

    return `
    <div class="path-card-premium" onclick="loadPage('path-roadmap', '${path.id}')">
        <!-- Header -->
        <div class="path-card-header">
            <div class="path-icon-lg">
                <i class="fas ${path.icon && !path.icon.includes('/') ? path.icon : 'fa-graduation-cap'}"></i>
            </div>
            <div>
                <span class="v6-badge mb-1 d-inline-block" style="font-size: 0.65rem; border: 1px solid ${path.color || '#8273DD'}; color: ${path.color || '#8273DD'}; padding: 2px 8px; border-radius: 12px;">
                    ${path.category === 'offensive' ? 'RED TEAM' : path.category === 'defensive' ? 'BLUE TEAM' : path.category === 'bounty' ? 'BUG BOUNTY' : 'CAREER PATH'}
                </span>
                <h4 class="text-white m-0" style="font-size: 1.1rem; line-height: 1.3;">${path.title}</h4>
            </div>
        </div>

        <!-- Description -->
        <p class="text-muted small mb-3 flex-grow-1" style="line-height: 1.6;">
            ${path.description ? (path.description.length > 80 ? path.description.substring(0, 80) + '...' : path.description) : 'Comprehensive career roadmap for cyber security professionals.'}
        </p>

        <!-- Stats Grid -->
        <div class="path-stats-grid">
            <div class="path-stat">
                <span class="path-stat-val">${courseCount}</span>
                <span class="path-stat-label">Courses</span>
            </div>
            <div class="path-stat">
                <span class="path-stat-val" style="color: ${difficultyColor}">${path.difficulty || 'Inter.'}</span>
                <span class="path-stat-label">Level</span>
            </div>
            <div class="path-stat">
                <span class="path-stat-val">${path.estimatedHours || 50}h</span>
                <span class="path-stat-label">Duration</span>
            </div>
        </div>
        
        <button class="path-action-btn">
            Explore Path <i class="fas fa-arrow-right ms-1"></i>
        </button>
    </div>
    `;
}

// 2. Course Card (Redesigned to match "Featured Paths")
function renderCourseCardV6(course) {
    // Determine color based on difficulty or random
    const colors = { 'Beginner': '#10B981', 'Intermediate': '#3b82f6', 'Advanced': '#ef4444' };
    const color = colors[course.difficulty] || '#8273DD';

    const iconClass = course.icon && course.icon.startsWith('fa-') ? course.icon : 'fa-graduation-cap';

    return `
    <div class="path-card-unified" style="--card-color: ${color}" onclick="loadPage('course-viewer', '${course.id}')">
        <div class="path-icon-wrapper" style="box-shadow: 0 0 20px ${color}33;">
            <div class="path-icon"><i class="fas ${iconClass}"></i></div>
        </div>
        <div class="path-info">
             <div class="d-flex align-items-center gap-2 mb-2">
                <span style="font-size: 0.7rem; background: rgba(255, 255, 255, 0.05); color: #fff; padding: 2px 8px; border-radius: 4px; font-weight: 800; letter-spacing: 1px;">COURSE</span>
                <span class="text-muted" style="font-size: 0.8rem;"><i class="fas fa-signal me-1"></i> ${course.difficulty}</span>
            </div>
            <h3>${course.title}</h3>
            <p>${course.description || 'Comprehensive course content including modules and labs.'}</p>
            <div class="path-progress-container">
                <div class="path-progress-bar" style="width: 0%"></div>
            </div>
            <span class="path-status" style="color: ${color}">Start Course <i class="fas fa-arrow-right"></i></span>
        </div>
    </div>
    `;
}

// Render specific Featured Path Card
function renderFeaturedPathCard(path) {
    const uData = window.UnifiedLearningData;
    let onClick = `loadPage('skill-tree')`;

    if (path.id) {
        if (uData.getPathById(path.id)) {
            onClick = `loadPage('path-roadmap', '${path.id}')`;
        } else if (uData.getCourseById(path.id)) {
            onClick = `loadPage('course-viewer', '${path.id}')`;
        }
    }

    const iconClass = path.icon || 'fa-map-signs';

    return `
    <div class="path-card-unified" style="--card-color: ${path.color}" onclick="${onClick}">
        <div class="path-icon-wrapper" style="box-shadow: 0 0 20px ${path.color}33;">
            <div class="path-icon"><i class="fas ${iconClass}"></i></div>
        </div>
        <div class="path-info">
            <div class="d-flex align-items-center gap-2 mb-2">
                <span style="font-size: 0.7rem; background: rgba(130, 115, 221, 0.2); color: #8273DD; padding: 2px 8px; border-radius: 4px; font-weight: 800; letter-spacing: 1px;">FEATURED PATH</span>
            </div>
            <h3>${path.title}</h3>
            <p>${path.desc}</p>
            <div class="path-progress-container">
                <div class="path-progress-bar" style="width: ${path.progress || 0}%"></div>
            </div>
            <span class="path-status" style="color: ${path.color}">Start Path <i class="fas fa-arrow-right"></i></span>
        </div>
    </div>
    `;
}

function renderModuleCardV6(mod) {
    const iconClass = mod.icon || 'fa-cube';
    const roomCount = Array.isArray(mod.rooms) ? mod.rooms.length : 0;
    const color = '#3b82f6'; // Default module color

    // Intelligent Routing: If module has rooms, it's a "Lab Module" -> Go to Room Viewer
    // (V2 Room Viewer handles both theory and lab tasks internally)
    const clickAction = (mod.rooms && mod.rooms.length > 0)
        ? `loadPage('room-viewer', '${mod.rooms[0]}')`
        : `loadPage('module-learning', '${mod.id}')`;

    return `
    <div class="path-card-unified" style="--card-color: ${color}" onclick="${clickAction}">
        <div class="path-icon-wrapper" style="box-shadow: 0 0 20px ${color}33;">
            <div class="path-icon"><i class="fas ${iconClass}"></i></div>
        </div>
        <div class="path-info">
            <div class="d-flex align-items-center gap-2 mb-2">
                <span style="font-size: 0.7rem; background: rgba(59, 130, 246, 0.2); color: #3b82f6; padding: 2px 8px; border-radius: 4px; font-weight: 800; letter-spacing: 1px;">MODULE</span>
                <span class="text-muted" style="font-size: 0.8rem;"><i class="fas fa-laptop-code me-1"></i> ${roomCount} Labs</span>
            </div>
            <h3>${mod.title}</h3>
            <p>${mod.description || 'Hands-on practice labs and theory modules.'}</p>
            <div class="path-progress-container">
                <div class="path-progress-bar" style="width: 0%"></div>
            </div>
            <span class="path-status" style="color: ${color}">Explore Labs <i class="fas fa-arrow-right"></i></span>
        </div>
    </div>
    `;
}

/* --- Pages --- */

/* Path Roadmap V6 (Standard Roadmap Style) */
function pagePathRoadmapV6(pathId) {
    if (!pathId) return pageLearningPathsV6();
    // Redirect existing logic to new professional details page
    return pagePathDetailsV6(pathId);
}

/* 1. NEW Path Details Page (Professional UI) */
function pagePathDetailsV6(pathId) {
    const uData = window.UnifiedLearningData;
    const path = uData.getPathById(pathId);
    if (!path) return `<div class="p-5 text-white">Path not found: ${pathId}</div>`;

    const courses = uData.getPathCourses(pathId);
    const progress = 0; // Placeholder

    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV6()}
        
        <div class="container pt-5">
            <div class="mb-4">
                <button onclick="history.back()" class="btn btn-outline-secondary btn-sm px-3 rounded-pill">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('رجوع', 'Back')}
                </button>
            </div>
            <div class="path-header-v6 fade-in">
                <div class="path-header-icon" style="--hh-purple: ${path.color || '#8273DD'};">
                    <i class="fas ${path.icon || 'fa-map-signs'}"></i>
                </div>
                <div class="flex-grow-1">
                    <div class="mb-2"><span class="badge bg-primary px-3 py-2 rounded-pill">CAREER PATH</span></div>
                    <h1 class="display-4 fw-black mb-2">${path.title}</h1>
                    <p class="text-muted fs-5 mb-4" style="max-width: 600px;">${path.description}</p>
                    
                    <div class="d-flex align-items-center gap-4">
                        <div style="width: 250px;">
                            <div class="d-flex justify-content-between mb-1 small fw-bold">
                                <span>PROGRESS</span>
                                <span>${progress}%</span>
                            </div>
                            <div class="path-progress-container">
                                <div class="path-progress-bar" style="width: ${progress}%"></div>
                            </div>
                        </div>
                        <button class="btn btn-primary px-5 py-3 fw-bold rounded-pill" onclick="loadPage('course-viewer', '${courses[0].id}')">
                            ${progress > 0 ? 'CONTINUE PATH' : 'ENROLL NOW'}
                        </button>
                    </div>
                </div>
            </div>

            <div class="row fade-in delay-1">
                <div class="col-lg-8">
                    <h2 class="mb-4 d-flex align-items-center gap-3">
                        <i class="fas fa-route text-primary"></i> The Roadmap
                    </h2>
                    <div class="timeline-container">
                        ${courses.map((c, i) => `
                            <div class="timeline-item ${i === 0 ? '' : 'locked'}" onclick="${i === 0 ? `loadPage('course-viewer', '${c.id}')` : ''}">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h4 class="text-white mb-1">${c.title}</h4>
                                        <p class="text-muted small mb-0">${c.description || 'Professional training modules.'}</p>
                                    </div>
                                    <div class="text-end">
                                        <span class="badge bg-dark border border-secondary mb-2">${c.rooms || 0} Tasks</span>
                                        <div class="small ${i === 0 ? 'text-warning' : 'text-muted'}">
                                            <i class="fas ${i === 0 ? 'fa-hourglass-half' : 'fa-lock'} me-1"></i> 
                                            ${i === 0 ? 'In Progress' : 'Locked'}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="section-divider mt-0">
                        <h2>Rewards</h2>
                        <div class="line"></div>
                    </div>
                    <div class="cert-preview">
                        <div class="mb-3 fw-bold text-white small">PATH COMPLETION CERTIFICATE</div>
                        <img src="assets/images/cert-mockup.png" class="cert-img-blur" alt="Certificate" onerror="this.style.display='none'">
                        <div class="cert-overlay">
                            <i class="fas fa-lock mb-3 fs-2 opacity-50"></i>
                            <h5 class="fw-bold mb-0">Locked</h5>
                            <p class="small text-muted">Complete all courses to unlock</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `;
}

/* Course Viewer V6 (Displays Modules) */
function pageCourseViewerV6(courseId) {
    console.log('DEBUG pageCourseViewerV6 called with courseId:', courseId);
    const uData = window.UnifiedLearningData;
    console.log('DEBUG UnifiedLearningData:', uData);
    console.log('DEBUG Available courses:', uData.courses ? uData.courses.map(c => c.id) : 'NO COURSES');
    const course = uData.getCourseById(courseId);
    console.log('DEBUG Found course:', course);
    if (!course) return `<div class="p-5 text-white">Course not found: ${courseId}<br><br>Available courses: ${uData.courses ? uData.courses.map(c => c.id).join(', ') : 'NONE'}</div>`;

    const modules = uData.getCourseModules(courseId);

    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV6()}
        <div class="learn-hero-v6 fade-in">
            <div class="container">
                <div class="mb-3"><span class="v6-badge">COURSE</span></div>
                <h1 class="display-4 fw-bold mb-3">${course.title}</h1>
                <p class="text-muted fs-5 mb-4" style="max-width: 700px; margin: 0 auto;">${course.description}</p>
            </div>
        </div>

        <div class="container fade-in delay-1">
             <div class="d-flex justify-content-between align-items-center mb-4">
                <h4 class="mb-0 text-white">Modules <span class="text-muted fs-6 ms-2">(${modules.length})</span></h4>
                <button onclick="history.back()" class="btn btn-outline-secondary btn-sm px-3 rounded-pill">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('رجوع', 'Back')}
                </button>
            </div>

            <div class="grid-3">
                ${modules.map(m => renderModuleCardV6(m)).join('')}
            </div>
        </div>
    </div>
    `;
}

/* Module Learning V6 (Displays Rooms) */
function pageModuleLearningV6(moduleId) {
    // Redirect to professional dashboard
    return pageLearningInterfaceV6(moduleId);
}

/* 2. NEW Learning Interface Dashboard (Split Screen) */
function pageLearningInterfaceV6(id, taskId = 0) {
    const uData = window.UnifiedLearningData;
    // Check if it's a module or course being viewed
    const module = uData.getModuleById(id);
    if (!module) return `<div class="p-5 text-white">Content not found: ${id}</div>`;

    const tasksRaw = module.tasks || [];
    let tasks = [...tasksRaw];

    // V6.1 FIX: Intelligent Task Normalization
    // If no tasks but MDX is present on the module itself (new structure), create a synthetic task
    if (tasks.length === 0 && module.mdxPath) {
        tasks = [{
            title: module.title,
            type: 'mdx',
            mdxPath: module.mdxPath,
            content: '', // Will be loaded by renderMDXTask
            vulnerability: module.vulnerability || null,
            codeCompare: module.codeCompare || null,
            questions: module.questions || null // Pass questions if any
        }];
    }

    const currentTask = tasks[taskId] || tasks[0] || { title: 'No Content', content: 'This module has no interactive tasks yet.' };

    // Trigger MDX loading if applicable
    if (currentTask.type === 'mdx' && currentTask.mdxPath) {
        setTimeout(() => renderMDXTask(currentTask.mdxPath, 'mdx-content-container'), 0);
    }

    return `
    ${getLearnStylesV6()}
    <div class="learn-interface fade-in">
        <!-- Sidebar -->
        <div class="sidebar-tasks">
            <div class="p-4 border-bottom border-secondary d-flex align-items-center justify-content-between">
                <div>
                    <h6 class="text-muted small mb-1">MODULE</h6>
                    <h5 class="m-0 text-white truncate-1">${module.title}</h5>
                </div>
                <button onclick="history.back()" class="btn btn-sm btn-outline-secondary rounded-pill px-3">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('رجوع', 'Back')}
                </button>
            </div>
            <div class="task-list">
                ${tasks.map((t, i) => `
                    <div class="task-nav-item ${i == taskId ? 'active' : ''}" onclick="loadPage('module-learning', '${id}', ${i})">
                        <div class="task-num">${i + 1}</div>
                        <div class="flex-grow-1">
                            <div class="text-white small fw-bold">${t.title}</div>
                            <div class="text-muted" style="font-size: 10px; text-transform: uppercase;">${t.type || 'Lesson'}</div>
                        </div>
                        ${i < taskId ? '<i class="fas fa-check-circle text-success fs-extra-small"></i>' : ''}
                    </div>
                `).join('')}
            </div>
            <div class="p-4 bg-dark border-top border-secondary">
                <button class="btn btn-danger btn-sm w-100" onclick="alert('Starting machine...')">
                    <i class="fas fa-power-off me-2"></i> START MACHINE
                </button>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-learning-content">
            <div class="content-header d-flex justify-content-between align-items-center">
                <h2 class="h4 m-0 fw-bold"><i class="fas fa-terminal text-primary me-2"></i> Task ${taskId + 1}: ${currentTask.title}</h2>
                <div class="d-flex gap-2">
                    <button class="btn btn-sm btn-outline-secondary"><i class="fas fa-bookmark"></i></button>
                    <button class="btn btn-sm btn-outline-secondary"><i class="fas fa-share"></i></button>
                </div>
            </div>

            <div class="content-body" id="mdx-content-container">
                <article class="markdown-content text-white-50">
                    ${currentTask.content || (currentTask.type === 'mdx' ? '<div class="text-center p-5"><i class="fas fa-spinner fa-spin fa-2x"></i><p class="mt-2">Loading Lesson...</p></div>' : 'No description available.')}
                    
                    ${currentTask.vulnerability ? `
                        <div class="alert alert-danger border-0 mt-4" style="background: rgba(239, 68, 68, 0.1);">
                            <h6 class="text-danger fw-bold"><i class="fas fa-bug"></i> Vulnerability Discovery</h6>
                            <p class="mb-0 text-white-50">${currentTask.vulnerability}</p>
                        </div>
                    ` : ''}
                    ${currentTask.codeCompare ? `
                        <div class="code-comparison-v6 mt-4">
                            <h6 class="fw-bold mb-3">Code Comparison</h6>
                            <div class="d-flex gap-3">
                                <div class="flex-grow-1">
                                    <span class="badge bg-danger mb-2">VULNERABLE</span>
                                    <div class="code-box" style="border-color: #ef4444;">${currentTask.codeCompare.vulnerable}</div>
                                </div>
                                <div class="flex-grow-1">
                                    <span class="badge bg-success mb-2">SECURE</span>
                                    <div class="code-box" style="border-color: #22c55e;">${currentTask.codeCompare.secure}</div>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                </article>
            </div>

            <!-- Footer Challenge -->
            <div class="lab-footer">
                ${currentTask.questions ? currentTask.questions.map(q => `
                    <div class="question-box mb-3">
                        <label class="d-block mb-3 fw-bold text-white">${q.text}</label>
                        <div class="d-flex gap-2">
                            <input type="text" class="form-control bg-dark border-secondary text-white" placeholder="Enter Flag or Answer...">
                            <button class="btn btn-primary px-4" onclick="this.parentElement.innerHTML='<div class=\'alert alert-success m-0 w-100\'><i class=\'fas fa-check-circle me-2\'></i> Correct!</div>'">Submit</button>
                        </div>
                    </div>
                `).join('') : `
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="text-muted small">Read the content above and mark as complete.</div>
                        <button class="btn btn-success px-5 fw-bold" onclick="loadPage('module-learning', '${id}', ${taskId + 1})">Complete & Next <i class="fas fa-arrow-right ms-2"></i></button>
                    </div>
                `}
    </div>
        </div >
    </div >
    `;
}

/* Standard Pages */
function pageLearningPathsV6() {
    const data = getIntegratedLearnDataV6();

    // Categorize Paths
    const antigravityPaths = data.paths.filter(p => p.id.startsWith('antigravity-'));
    const legacyPaths = data.paths.filter(p => !p.id.startsWith('antigravity-'));

    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV6()}
        <div class="learn-hero-v6 fade-in">
            <div class="container text-start">
                <button onclick="loadPage('learn')" class="btn btn-outline-secondary btn-sm mb-4 px-3 rounded-pill">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('رجوع', 'Back')}
                </button>
                <h1 class="display-4 fw-bold mb-3">BreachLabs Academy</h1>
                <p class="text-muted fs-5">Premium cybersecurity specializations and legacy career tracks.</p>
            </div>
        </div>
        <div class="container">
            <!-- Antigravity Specialization Section -->
            <div id="antigravity-specializations" class="section-divider fade-in delay-1">
                <h2 class="text-info"><i class="fas fa-bolt me-2"></i> BreachLabs Specializations</h2>
                <div class="line" style="background: var(--hh-blue);"></div>
            </div>
            <div class="grid-3 mb-5">${antigravityPaths.map(renderPathCardV6).join('')}</div>

            <!-- Legacy Career Tracks Section -->
            <div id="legacy-tracks" class="section-divider fade-in delay-2" style="opacity: 0.7;">
                <h2><i class="fas fa-history me-2"></i> Legacy Career Tracks</h2>
                <div class="line"></div>
            </div>
            <div class="grid-3">${legacyPaths.map(renderPathCardV6).join('')}</div>
        </div>
    </div>
    `;
}

function pageCoursesV6() {
    const data = getIntegratedLearnDataV6();

    // Featured Paths Data (Imported from Home Page properties)
    const featuredPaths = [
        { title: 'Red Teaming', icon: 'fa-user-secret', color: '#ef4444', desc: 'Offensive Security & Pentesting', progress: 0, id: 'red-team-path' },
        { title: 'Exploit Dev', icon: 'fa-bomb', color: '#7f1d1d', desc: 'Buffer Overflows & Shellcoding', progress: 0, id: 'exploit-development-path' },
        { title: 'Bug Bounty Hunter', icon: 'fa-bug', color: '#f59e0b', desc: 'Turn your hacking skills into income. Learn to find vulnerabilities in real-world applications.', progress: 0, id: 'bug-bounty-path' },
        { title: 'OWASP Top 10', icon: 'fa-file-shield', color: '#005ea2', desc: 'OWASP Top 10 2021 Deep Dive & Exploitation.', progress: 0, id: 'owasp-top10-deep' },
        { title: 'Web Dev for Pentesters', icon: 'fa-code', color: '#10B981', desc: 'Secure Coding & Backend Logic', progress: 0, id: 'web-dev-pentest-path' },
        { title: 'Advanced Networking', icon: 'fa-network-wired', color: '#3b82f6', desc: 'Enterprise Protocols & Infra', progress: 0, id: 'adv-network-path' },
        { title: 'Web Architecture', icon: 'fa-cubes', color: '#00d4ff', desc: 'Secure Design & Exploitation', progress: 0, id: 'web-security-architecture-path' }
    ];

    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV6()}
        
        <div class="learn-hero-v6 fade-in">
            <div class="container text-start">
                <button onclick="loadPage('learn')" class="btn btn-outline-secondary btn-sm mb-4 px-3 rounded-pill">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('رجوع', 'Back')}
                </button>
                <h1 class="display-4 fw-bold mb-3">Professional Courses</h1>
                <p class="text-muted fs-5">Advanced specialized training tracks.</p>
            </div>
        </div>
        
        <div class="container">
            <!-- Featured Paths Section -->
            <div class="section-divider fade-in delay-1">
                <h2>Featured Paths</h2>
                <div class="line"></div>
            </div>
            
            <div class="grid-3 fade-in delay-1">
                ${featuredPaths.map(renderFeaturedPathCard).join('')}
            </div>

            <!-- All Courses Section -->
            <div class="section-divider fade-in delay-2">
                <h2>All Courses</h2>
                <div class="line"></div>
            </div>
            
            <div class="grid-3 fade-in delay-2">
                ${data.courses.map(renderCourseCardV6).join('')}
            </div>
        </div>
    </div>
    `;
}

function pageModulesV6() {
    const data = getIntegratedLearnDataV6();
    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV6()}
        <div class="learn-hero-v6 fade-in">
            <div class="container text-start">
                <button onclick="loadPage('learn')" class="btn btn-outline-secondary btn-sm mb-4 px-3 rounded-pill">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('رجوع', 'Back')}
                </button>
                <h1 class="display-4 fw-bold mb-3">All Modules</h1>
            </div>
        </div>
        <div class="container">
            <div class="grid-3">${data.modules.map(renderModuleCardV6).join('')}</div>
        </div>
    </div>
    `;
}

function pageHubV6() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV6()}
        <div class="learn-hero-v6 fade-in">
            <div class="container">
                <h1 class="display-4 fw-bold mb-3">BreachLabs Academy <span style="font-size:1rem; color:var(--hh-purple);">V6</span></h1>
                <p class="text-muted text-uppercase letter-spacing-2 small fw-bold">Professional Cyber Learning Hub</p>
            </div>
        </div>
        <div class="container">
            <div class="grid-3">

                <div class="path-card-v6" onclick="loadPage('courses')">
                    <div class="v6-header"><img src="assets/images/3d-icons/icon_pentest_3d_1765819812403.png" class="v6-icon-img"></div>
                    <div class="v6-body text-center"><h3 class="v6-title">Courses</h3><div class="v6-footer-btn">Browse Courses</div></div>
                </div>
                <div class="path-card-v6" onclick="loadPage('learning-paths')">
                    <div class="v6-header"><img src="assets/images/3d-icons/icon_learning_path_3d_1765922272083.png" class="v6-icon-img"></div>
                    <div class="v6-body text-center"><h3 class="v6-title">Learning Paths</h3><div class="v6-footer-btn">Browse Paths</div></div>
                </div>
                <div class="path-card-v6" onclick="loadPage('modules')">
                    <div class="v6-header"><img src="assets/images/3d-icons/icon_security_3d_1765817313667.png" class="v6-icon-img"></div>
                    <div class="v6-body text-center"><h3 class="v6-title">Modules</h3><div class="v6-footer-btn">Browse Modules</div></div>
                </div>
            </div>
        </div>
    </div>
    `;
}

/* --- MDX RENDERING KERNEL --- */

async function renderMDXTask(mdxPath, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    try {
        console.log('MDX-Kernel: Fetching...', mdxPath);
        const response = await fetch(mdxPath);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const text = await response.text();

        // Parse MDX (Markdown + Custom Components)
        const html = basicMDXParser(text);

        // Calculate Read Time (approx 200 words per minute)
        const words = text.split(/\s+/).length;
        const readTime = Math.ceil(words / 200);

        container.innerHTML = `
            <div class="mdx-header-meta mb-4 d-flex justify-content-between align-items-center fade-in">
                <div class="d-flex gap-3 align-items-center text-muted small">
                    <span><i class="far fa-clock me-1"></i> ${readTime} min read</span>
                    <span><i class="far fa-file-alt me-1"></i> ${words} words</span>
                </div>
                <div class="lesson-progress-container flex-grow-1 mx-4" style="height: 4px; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden;">
                    <div id="lesson-scroll-progress" style="width: 0%; height: 100%; background: var(--hh-blue); transition: width 0.3s ease;"></div>
                </div>
            </div>

            <article class="markdown-content text-white-50 fade-in">
                ${html}
                <div class="mt-5 pt-4 border-top border-secondary">
                    <button class="btn btn-success px-4 py-2 fw-bold" onclick="markTaskComplete()">
                        <i class="fas fa-check-circle me-2"></i> MARK TASK AS COMPLETE
                    </button>
                </div>
            </article>
        `;

        // Scroll listener for progress bar
        const scrollContainer = container.closest('.content-body') || window;
        scrollContainer.onscroll = () => {
            const winScroll = scrollContainer.scrollTop || document.documentElement.scrollTop;
            const height = (scrollContainer.scrollHeight || document.documentElement.scrollHeight) - (scrollContainer.clientHeight || window.innerHeight);
            const scrolled = (winScroll / height) * 100;
            const progBar = document.getElementById('lesson-scroll-progress');
            if (progBar) progBar.style.width = scrolled + "%";
        };

        // Post-render: Initialize Terminal or other JS components if found in HTML
        if (html.includes('terminal-window')) {
            setTimeout(initLessonTerminals, 100);
        }

    } catch (err) {
        console.error('MDX-Kernel Error:', err);
        container.innerHTML = `
            <div class="alert alert-danger m-4">
                <h5 class="fw-bold"><i class="fas fa-exclamation-triangle"></i> MDX Load Failure</h5>
                <p class="mb-0">Path: <code>${mdxPath}</code></p>
                <p class="small opacity-50 mb-0">${err.message}</p>
            </div>
        `;
    }
}

function basicMDXParser(text) {
    if (!text) return 'No content.';
    let md = text;

    // 1. STRIP MDX Frontmatter if exists
    md = md.replace(/^---[\s\S]*?---/, '');

    // 2. MDX SPECIAL COMPONENTS (Antigravity Suite)

    // Terminal Window
    md = md.replace(/<TerminalWindow\s*title="([^"]*)"\s*command="([^"]*)"\s*output="([^"]*)"\s*\/>/gim, `
        <div class="terminal-lesson-wrapper my-4">
            <div class="terminal-header d-flex align-items-center justify-content-between bg-dark px-3 py-2 border-bottom border-secondary">
                <div class="d-flex gap-2">
                    <span class="dot bg-danger"></span>
                    <span class="dot bg-warning"></span>
                    <span class="dot bg-success"></span>
                </div>
                <div class="text-muted small">$1</div>
            </div>
            <div class="terminal-body bg-black p-3 font-monospace" style="min-height: 100px;">
                <div class="text-success mb-1">$ <span class="text-white">$2</span></div>
                <div class="text-white-50 small mb-2">$3</div>
                <div class="terminal-cursor"></div>
            </div>
        </div>
    `);

    // InfoBox (Alert-like) - Glassmorphism Update
    md = md.replace(/<InfoBox\s*type="([^"]*)"\s*>([\s\S]*?)<\/InfoBox>/gim, (match, type, content) => {
        const icon = type === 'warning' ? 'exclamation-triangle' : (type === 'important' ? 'fire' : 'info-circle');
        const color = type === 'warning' ? 'warning' : (type === 'important' ? 'danger' : 'info');
        return `
            <div class="alert alert-${color} border-0 my-4 glass-box" style="background: rgba(var(--bs-${color}-rgb), 0.05); backdrop-filter: blur(10px); border: 1px solid rgba(var(--bs-${color}-rgb), 0.2) !important;">
                <h6 class="fw-bold text-${color} text-uppercase letter-spacing-1"><i class="fas fa-${icon} me-2 animate-pulse"></i> ${type}</h6>
                <div class="mb-0 text-white-70">${content}</div>
            </div>
        `;
    });

    // ... Quiz, PacketView etc ...

    // Quiz Component (Enhanced with Hint System)
    md = md.replace(/<Quiz\s*question="([^"]*)"\s*answer="([^"]*)"\s*hint="([^"]*)"\s*\/>/gim, (match, q, a, h) => {
        const id = 'quiz-' + Math.random().toString(36).substr(2, 9);
        return `
            <div class="quiz-card-lesson my-4 p-4 glass-box rounded-3 border-start border-4 border-primary">
                <h6 class="text-info mb-3"><i class="fas fa-question-circle me-2"></i> KNOWLEDGE CHECK</h6>
                <p class="text-white mb-4 fw-bold">${q}</p>
                <div class="d-flex gap-2 mb-3">
                    <input type="text" id="${id}-input" class="form-control bg-black border-secondary text-white" placeholder="Enter Answer..." onkeyup="if(event.key==='Enter') checkLessonQuiz('${id}', '${a}')">
                    <button class="btn btn-primary px-4" onclick="checkLessonQuiz('${id}', '${a}')">Submit</button>
                </div>
                <div id="${id}-feedback"></div>
                ${h ? `
                    <div class="mt-3">
                        <button class="btn btn-link btn-sm text-muted p-0 text-decoration-none" onclick="toggleQuizHint('${id}-hint')">
                            <i class="fas fa-lightbulb me-1"></i> Need a hint? <span class="small text-danger ms-1">(-10 XP Penalty)</span>
                        </button>
                        <div id="${id}-hint" class="d-none mt-2 p-3 bg-black bg-opacity-50 rounded border border-warning border-opacity-25 text-warning small italic">
                            <i class="fas fa-info-circle me-2"></i> HINT: ${h}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    });

    // PacketView (Network Visualization)
    md = md.replace(/<PacketView\s*source="([^"]*)"\s*dest="([^"]*)"\s*protocol="([^"]*)"\s*flags="([^"]*)"\s*seq="([^"]*)"\s*\/>/gim, `
        <div class="packet-analyzer-lesson my-4 p-3 border border-secondary rounded-3 bg-dark">
            <div class="mb-2 small text-uppercase text-muted letter-spacing-1">Network Packet Capture</div>
            <div class="d-flex align-items-center justify-content-between gap-3 text-white">
                <div class="text-center">
                    <div class="text-info fw-bold mb-1">SRC</div>
                    <div class="small">$1</div>
                </div>
                <div class="flex-grow-1 text-center position-relative">
                    <div class="text-success small mb-1">$3 ($4)</div>
                    <div style="height:2px; background:var(--bs-success); position:relative;">
                        <i class="fas fa-chevron-right text-success" style="position:absolute; right:0; top:-7px;"></i>
                    </div>
                </div>
                <div class="text-center">
                    <div class="text-warning fw-bold mb-1">DST</div>
                    <div class="small">$2</div>
                </div>
            </div>
            <div class="mt-2 text-center small text-muted font-monospace">SEQ: $5 | FLAGS: $4</div>
        </div>
    `);

    // CodeCompare Component
    md = md.replace(/<CodeCompare\s*vulnerable="([^"]*)"\s*secure="([^"]*)"\s*\/>/gim, `
        <div class="code-comparison-lesson my-4">
            <div class="row g-3">
                <div class="col-md-6">
                    <div class="card bg-dark border-danger border-opacity-25 h-100">
                        <div class="card-header bg-danger bg-opacity-10 text-danger border-danger border-opacity-25 py-2 fw-bold">
                            <i class="fas fa-bug me-2"></i> VULNERABLE
                        </div>
                        <div class="card-body p-0">
                            <pre class="bg-black p-3 m-0 text-white-50 font-monospace small" style="border-radius: 0 0 4px 4px;">$1</pre>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card bg-dark border-success border-opacity-25 h-100">
                        <div class="card-header bg-success bg-opacity-10 text-success border-success border-opacity-25 py-2 fw-bold">
                            <i class="fas fa-shield-halved me-2"></i> SECURE
                        </div>
                        <div class="card-body p-0">
                            <pre class="bg-black p-3 m-0 text-white-50 font-monospace small" style="border-radius: 0 0 4px 4px;">$2</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `);

    // ChallengeBox Component
    md = md.replace(/<ChallengeBox\s*title="([^"]*)"\s*>([\s\S]*?)<\/ChallengeBox>/gim, `
        <div class="challenge-box-lesson p-4 border border-primary border-opacity-25 rounded-3 my-4" style="background: rgba(var(--bs-primary-rgb), 0.03);">
            <div class="d-flex align-items-center mb-3">
                <div class="badge bg-primary me-3 px-3 py-2">CHALLENGE</div>
                <h5 class="m-0 text-white">$1</h5>
            </div>
            <div class="challenge-tasks text-white-50">$2</div>
        </div>
    `);

    // 3. STANDARD MARKDOWN (Extended basicMarkdown)
    // Headers
    md = md.replace(/^# (.*$)/gim, '<h1 class="text-success border-bottom border-secondary pb-3 mb-4 display-5 fw-bold">$1</h1>');
    md = md.replace(/^## (.*$)/gim, '<h2 class="text-white mt-5 mb-3 fw-bold"><i class="fas fa-caret-right text-primary me-2"></i> $1</h2>');
    md = md.replace(/^### (.*$)/gim, '<h3 class="text-white mt-4 mb-2">$1</h3>');

    // Bold & Italic
    md = md.replace(/\*\*(.*)\*\*/gim, '<strong class="text-white">$1</strong>');
    md = md.replace(/\*(.*)\*/gim, '<em>$1</em>');

    // Code blocks & Inline code
    const renderCodeBlock = (lang, content) => {
        const id = 'code-' + Math.random().toString(36).substr(2, 9);
        return `
            <div class="code-block-lesson my-4 position-relative group">
                <div class="code-header d-flex justify-content-between align-items-center">
                    <span>${lang.toUpperCase()}</span>
                    <button class="btn btn-link btn-sm text-muted p-0 text-decoration-none hover-white" onclick="copyLessonCode('${id}')">
                        <i class="far fa-copy me-1"></i> Copy
                    </button>
                </div>
                <pre id="${id}" class="bg-black p-3 rounded-bottom border border-secondary border-top-0 font-monospace" style="color: ${lang === 'python' ? 'var(--hh-gold)' : (lang === 'javascript' ? 'var(--hh-blue)' : 'var(--hh-green)')}">${content}</pre>
            </div>
        `;
    };

    md = md.replace(/```bash([\s\S]*?)```/gim, (m, c) => renderCodeBlock('bash', c));
    md = md.replace(/```python([\s\S]*?)```/gim, (m, c) => renderCodeBlock('python', c));
    md = md.replace(/```javascript([\s\S]*?)```/gim, (m, c) => renderCodeBlock('javascript', c));
    md = md.replace(/```([\s\S]*?)```/gim, (m, c) => renderCodeBlock('code', c));
    md = md.replace(/`([^`]+)`/gim, '<code class="bg-secondary bg-opacity-25 px-2 py-0.5 rounded text-warning">$1</code>');

    // Lists (nested and single)
    md = md.replace(/^\s*-\s+(.*)/gim, '<li class="mb-2 list-unstyled"><i class="fas fa-chevron-circle-right text-success me-2 small"></i>$1</li>');

    // Images & Links
    md = md.replace(/!\[(.*?)\]\((.*?)\)/gim, '<div class="text-center my-4"><img src="$2" alt="$1" class="img-fluid rounded border border-secondary shadow-lg"><p class="small text-muted mt-2">$1</p></div>');
    md = md.replace(/\[(.*?)\]\((.*?)\)/gim, '<a href="$2" target="_blank" class="text-primary text-decoration-none border-bottom border-primary border-opacity-25">$1 <i class="fas fa-external-link-alt fs-extra-small"></i></a>');

    // Paragraphs
    md = md.replace(/\n\n/g, '<p class="mb-4">');

    return md;
}

/* Global Lesson Quiz Handler */

/* Terminal Animation Logic */
function initLessonTerminals() {
    const terminals = document.querySelectorAll('.terminal-body');
    terminals.forEach(term => {
        term.classList.add('active');
        const commandText = term.querySelector('.text-white');
        const outputText = term.querySelector('.text-white-50');

        if (commandText && !commandText.dataset.typed) {
            const originalCommand = commandText.innerText;
            const originalOutput = outputText ? outputText.innerText : "";

            commandText.innerText = '';
            if (outputText) outputText.style.opacity = '0';

            let i = 0;
            const typeCommand = () => {
                if (i < originalCommand.length) {
                    commandText.innerText += originalCommand.charAt(i);
                    i++;
                    setTimeout(typeCommand, Math.random() * 50 + 30); // Realistic speed
                } else {
                    // Show output after delay
                    setTimeout(() => {
                        if (outputText) {
                            outputText.style.transition = 'opacity 0.5s ease';
                            outputText.style.opacity = '1';
                        }
                    }, 500);
                }
            };
            setTimeout(typeCommand, 800);
            commandText.dataset.typed = "true";
        }
    });
}

/* Global Lesson Quiz Handler */
window.checkLessonQuiz = function (question, answer) {
    const input = document.getElementById(`quiz-ans-${question}`);
    if (!input) return;

    if (input.value.trim().toLowerCase() === answer.toLowerCase()) {
        input.classList.remove('is-invalid');
        input.classList.add('is-valid');
        if (typeof showToast === 'function') showToast('Excellent! Correct Answer.', 'success');
        // Add XP
        if (window.gamification) window.gamification.addXP(50, 'Lesson Quiz Solved');
    } else {
        input.classList.add('is-invalid');
        if (typeof showToast === 'function') showToast('Keep trying...', 'danger');
    }
};

window.markTaskComplete = function () {
    if (typeof showToast === 'function') showToast('Achievement Unlocked: Step Closer to Mastery!', 'success');
    history.back();
};

/* Copy Code Helper */
window.copyLessonCode = function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.innerText).then(() => {
        if (typeof showToast === 'function') showToast('Code copied to clipboard!', 'success');
    });
};

/* Quiz Helpers */
window.checkLessonQuiz = function (id, answer) {
    const input = document.getElementById(id + '-input');
    const feedback = document.getElementById(id + '-feedback');
    if (input.value.trim().toLowerCase() === answer.toLowerCase()) {
        feedback.innerHTML = `<div class='alert alert-success mt-2 mb-0 py-2'><i class='fas fa-check-circle me-2'></i> Perfect! Correct Answer.</div>`;
        if (typeof showToast === 'function') showToast('Challenge completed!', 'success');
    } else {
        feedback.innerHTML = `<div class='alert alert-danger mt-2 mb-0 py-2'><i class='fas fa-times-circle me-2'></i> Incorrect. Try again.</div>`;
    }
};

window.toggleQuizHint = function (hintId) {
    const el = document.getElementById(hintId);
    el.classList.toggle('d-none');
    if (!el.classList.contains('d-none') && typeof showToast === 'function') {
        showToast('Hint revealed! -10 XP penalty applied.', 'warning');
    }
};

/* Exports */
window.pageHubV6 = pageHubV6;
window.pageCoursesV6 = pageCoursesV6;
window.pageLearningPathsV6 = pageLearningPathsV6;
window.pageModulesV6 = pageModulesV6;
// New Hierarchy Exports
window.pagePathRoadmap = pagePathRoadmapV6;
window.pageCourseViewer = pageCourseViewerV6;
window.pageModuleLearning = pageModuleLearningV6;
console.log('✅ learn-section-v6.js exports applied.');

// Legacy Redirects
window.getLearnStylesV6 = getLearnStylesV6;
window.getIntegratedLearnDataV6 = getIntegratedLearnDataV6;
window.renderCourseCardV6 = renderCourseCardV6;
window.renderPathCardV6 = renderPathCardV6;
window.pageLearningPathsV5 = pageLearningPathsV6;
window.pageLearningPathsPro = pageLearningPathsV6;
window.pageModulesPro = pageModulesV6;
window.pageLearnV2 = pageHubV6;
window.pageLearn = pageHubV6;

