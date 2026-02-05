
/* page_v2.js – Dynamic V2 Content (Courses & CTF) */

// Helper to fetch data safely
const SERVER_BASE = 'http://localhost:5000';

async function fetchV2(endpoint) {
    try {
        const response = await fetch(`${SERVER_BASE}${endpoint}`);
        const data = await response.json();
        return data.success ? data : null;
    } catch (error) {
        console.error("V2 API Error:", error);
        return null;
    }
}

// ==================== COURSES PAGE ====================

// Attach to window for global access
window.pageCoursesV2 = function () {
    // Return placeholder and trigger load
    setTimeout(loadCoursesData, 0);
    return `<div id="v2-courses-container" class="text-center mt-5"><i class="fas fa-circle-notch fa-spin fa-3x text-success"></i></div>`;
}

// Attach to window
window.pageCTFV2 = function () {
    setTimeout(loadCTFData, 0);
    return `<div id="v2-ctf-container" class="text-center mt-5"><i class="fas fa-circle-notch fa-spin fa-3x text-warning"></i></div>`;
}

// Attach to window
window.pageLeaderboard = function () {
    setTimeout(loadLeaderboardData, 0);
    return `<div id="v2-leaderboard-container" class="text-center mt-5"><i class="fas fa-circle-notch fa-spin fa-3x text-warning"></i></div>`;
}

async function loadCoursesData() {
    const container = document.getElementById('v2-courses-container');
    if (!container) return;

    const data = await fetchV2('/api/v2/courses');

    if (!data || !data.courses) {
        container.innerHTML = `<div class="alert alert-danger text-center">Failed to load courses.</div>`;
        return;
    }

    let html = `
    <div class="container mt-4 fade-in">
        <div class="hero-section text-center mb-5 p-5 rounded-3" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white;">
            <h1 class="display-4 fw-bold"><i class="fas fa-graduation-cap me-3"></i>Academy</h1>
            <p class="lead opacity-75">Master cybersecurity with our structured learning paths.</p>
        </div>
        
        <div class="row g-4">`;

    data.courses.forEach(course => {
        html += `
        <div class="col-md-6 col-lg-4">
            <div class="card h-100 bg-dark text-white border-secondary hover-lift">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <i class="fas ${course.icon || 'fa-book'} fa-2x text-success"></i>
                        <span class="badge bg-${course.difficulty === 'Beginner' ? 'success' : 'warning'}">${course.difficulty}</span>
                    </div>
                    <h3 class="card-title h4">${course.title}</h3>
                    <p class="card-text text-muted">Contains ${course.units ? course.units.length : 0} learning units</p>
                    
                    <button onclick="renderCourseDetail(${course.id})" class="btn btn-outline-success w-100 mt-3">
                        Start Learning <i class="fas fa-arrow-right ms-2"></i>
                    </button>
                </div>
            </div>
        </div>`;
    });

    html += `</div></div>`;
    container.innerHTML = html;
}

// Make globally available for button clicks
// Global cache for current course content
let currentCourseData = null;

// Make globally available for button clicks
window.renderCourseDetail = async function (courseId) {
    // We target the main content area directly for detail view
    const container = document.getElementById('content');
    if (!container) return;

    container.innerHTML = `<div class="text-center mt-5"><i class="fas fa-circle-notch fa-spin fa-3x text-success"></i></div>`;

    const data = await fetchV2(`/api/v2/courses/${courseId}`);

    if (!data || !data.course) {
        container.innerHTML = `<div class="alert alert-danger">Course not found.</div>`;
        return;
    }

    const c = data.course;
    currentCourseData = c; // Store for lesson access

    let html = `
    <div class="container mt-4 fade-in">
        <div class="d-flex justify-content-between align-items-center mb-3">
             <button onclick="loadPage('courses')" class="btn btn-link text-white text-decoration-none"><i class="fas fa-arrow-left"></i> Back to Courses</button>
        </div>
        
        <div class="card bg-dark text-white border-0 mb-4">
            <div class="card-body p-4">
                <h1 class="display-5 text-success"><i class="fas ${c.icon} me-3"></i>${c.title}</h1>
                <div class="d-flex gap-2">
                    <span class="badge bg-secondary">${c.difficulty}</span>
                    <span class="badge bg-dark border border-secondary">${c.units.length} Units</span>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-4 mb-4">
                <h4 class="text-white mb-3">Syllabus</h4>
                <div class="accordion" id="unitsAccordion">`;

    c.units.forEach((unit, uIndex) => {
        const collapseId = `v2-unit-collapse-${unit.id}`;
        const headingId = `v2-unit-heading-${unit.id}`;

        html += `
        <div class="accordion-item bg-dark text-white border-secondary mb-2 rounded overflow-hidden">
            <h2 class="accordion-header" id="${headingId}">
                <button class="accordion-button ${uIndex !== 0 ? 'collapsed' : ''} bg-dark text-white shadow-none" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="${uIndex === 0}" aria-controls="${collapseId}">
                    <span class="fw-bold text-success me-2">${uIndex + 1}.</span> ${unit.title}
                </button>
            </h2>
            <div id="${collapseId}" class="accordion-collapse collapse ${uIndex === 0 ? 'show' : ''}" aria-labelledby="${headingId}" data-bs-parent="#unitsAccordion">
                <div class="accordion-body bg-darker p-0">
                    <div class="list-group list-group-flush">`;

        unit.lessons.forEach((lesson, lIndex) => {
            // Check if it's a lab or text lesson
            const isLab = !!lesson.connected_lab_id;
            const icon = isLab ? 'fa-flask' : 'fa-file-alt';

            html += `
            <button type="button" onclick="openLesson(event, ${uIndex}, ${lIndex})" class="list-group-item list-group-item-action bg-transparent text-white-50 border-secondary d-flex justify-content-between align-items-center py-3">
                <div class="d-flex align-items-center text-truncate">
                    <i class="fas ${icon} me-3 width-20 text-center"></i>
                    <span class="text-truncate">${lesson.title}</span>
                </div>
                ${isLab ? '<span class="badge bg-danger ms-2">LAB</span>' : ''}
            </button>`;
        });

        html += `   </div>
                </div>
            </div>
        </div>`;
    });

    html += `   </div>
            </div>
            
            <div class="col-lg-8">
                <div id="lesson-content-viewer" class="card bg-dark border-secondary h-100 min-vh-50">
                    <div class="card-body d-flex flex-column justify-content-center align-items-center text-muted p-5">
                        <i class="fas fa-book-reader fa-4x mb-3 opacity-50"></i>
                        <h3>Select a lesson to start learning</h3>
                        <p>Choose a topic from the syllabus on the left.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>`;

    container.innerHTML = html;
}

// Open Lesson Function
window.openLesson = function (event, uIndex, lIndex) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    if (!currentCourseData) return;

    const unit = currentCourseData.units[uIndex];
    if (!unit) return;

    const lesson = unit.lessons[lIndex];
    if (!lesson) return;

    const viewer = document.getElementById('lesson-content-viewer');

    // Highlight active lesson
    document.querySelectorAll('.list-group-item').forEach(el => el.classList.remove('active', 'border-success', 'bg-dark-subtle'));
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active', 'border-success', 'bg-dark-subtle');
    }

    let contentHtml = '';

    if (lesson.connected_lab_id) {
        // Lab View
        contentHtml = `
            <div class="card-body text-center p-5">
                <div class="mb-4">
                    <span class="badge bg-danger mb-2">PRACTICAL LAB</span>
                    <h2 class="text-white">${lesson.title}</h2>
                </div>
                <div class="alert alert-dark border-secondary text-start mb-4">
                    <i class="fas fa-info-circle text-info me-2"></i>
                    This lesson involves a hands-on laboratory environment.
                </div>
                <button onclick="loadPage('room-viewer', '${lesson.connected_lab_id}')" class="btn btn-success btn-lg px-5">
                    <i class="fas fa-rocket me-2"></i> Launch Lab Environment
                </button>
            </div>
        `;
    } else {
        // Text Content View (Internal Simple Markdown)
        // This avoids external library dependency issues (marked.js)
        const basicMarkdown = (text) => {
            if (!text) return 'No content available.';
            let md = text;

            // Headers
            md = md.replace(/^# (.*$)/gim, '<h1 class="text-success border-bottom border-secondary pb-2 mb-4">$1</h1>');
            md = md.replace(/^## (.*$)/gim, '<h2 class="text-white mt-4 mb-3">$1</h2>');
            md = md.replace(/^### (.*$)/gim, '<h3 class="text-white mt-3 mb-2">$1</h3>');

            // Bold & Italic
            md = md.replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>');
            md = md.replace(/\*(.*)\*/gim, '<em>$1</em>');

            // Code blocks
            md = md.replace(/```bash([\s\S]*?)```/gim, '<pre class="bg-black p-3 rounded border border-secondary text-success font-monospace mb-3">$1</pre>');
            md = md.replace(/```([\s\S]*?)```/gim, '<pre class="bg-black p-3 rounded border border-secondary text-white font-monospace mb-3">$1</pre>');
            md = md.replace(/`([^`]+)`/gim, '<code class="bg-dark px-1 rounded text-warning">$1</code>');

            // Lists
            md = md.replace(/^\s*-\s+(.*)/gim, '<li class="mb-1"><i class="fas fa-angle-right text-success me-2 small"></i>$1</li>');

            // Image/Links (Basic)
            md = md.replace(/\[(.*?)\]\((.*?)\)/gim, '<a href="$2" target="_blank" class="text-success text-decoration-none">$1</a>');

            // Paragraphs (newlines)
            md = md.replace(/\n\n/g, '<p class="mb-3">');
            md = md.replace(/\n/g, '<br>');

            return md;
        };

        const safeContent = basicMarkdown(lesson.content_markdown || 'No content available.');

        contentHtml = `
            <div class="card-header border-secondary bg-transparent d-flex justify-content-between align-items-center">
                <h3 class="h4 mb-0 text-white">${lesson.title}</h3>
                <span class="text-muted">Unit ${uIndex + 1} / Lesson ${lIndex + 1}</span>
            </div>
            <div class="card-body p-4 markdown-content text-white-50" style="line-height: 1.7;">
                ${safeContent}
            </div>
            <div class="card-footer border-secondary bg-transparent">
                <button class="btn btn-outline-success float-end">
                    <i class="fas fa-check me-2"></i> Mark as Complete
                </button>
            </div>
        `;
    }

    viewer.innerHTML = contentHtml;
    // Scroll viewer into view on mobile
    if (window.innerWidth < 992) {
        viewer.scrollIntoView({ behavior: 'smooth' });
    }
};

// ==================== CTF CHALLENGES PAGE ====================

function pageCTFV2() {
    setTimeout(loadCTFData, 0);
    return `<div id="v2-ctf-container" class="text-center mt-5"><i class="fas fa-circle-notch fa-spin fa-3x text-warning"></i></div>`;
}

async function loadCTFData() {
    const container = document.getElementById('v2-ctf-container');
    if (!container) return;

    const data = await fetchV2('/api/v2/challenges');

    if (!data || !data.challenges) {
        container.innerHTML = `<div class="alert alert-danger">Failed to load challenges.</div>`;
        return;
    }

    let html = `
    <div class="container mt-4 fade-in">
        <div class="d-flex justify-content-between align-items-center mb-5">
            <div>
                <h1 class="fw-bold text-warning"><i class="fas fa-flag me-2"></i>CTF Arena</h1>
                <p class="text-muted">Test your skills with real-world challenges</p>
            </div>
            <div class="bg-dark p-3 rounded border border-warning">
                <span class="text-warning fw-bold">YOUR SCORE:</span> <span class="text-white">0 PTS</span>
            </div>
        </div>
        
        <div class="row g-4">`;

    data.challenges.forEach(ch => {
        html += `
        <div class="col-md-6 col-lg-4">
            <div class="card bg-dark text-white border-secondary h-100 position-relative hover-scale">
                <div class="position-absolute top-0 end-0 m-3">
                    <span class="badge bg-warning text-dark">${ch.points} PTS</span>
                </div>
                <div class="card-body d-flex flex-column">
                    <div class="mb-3">
                        <span class="badge bg-primary bg-opacity-25 text-primary border border-primary">${ch.category}</span>
                        <span class="badge bg-${ch.difficulty === 'Easy' ? 'success' : 'danger'} bg-opacity-25 text-${ch.difficulty === 'Easy' ? 'success' : 'danger'} border border-${ch.difficulty === 'Easy' ? 'success' : 'danger'} ms-1">${ch.difficulty}</span>
                    </div>
                    <h3 class="card-title h5 mb-3">${ch.title}</h3>
                    <p class="card-text text-muted small flex-grow-1">${ch.description}</p>
                    
                    <div class="mt-3">
                        <div class="input-group mb-2">
                            <input type="text" class="form-control bg-black text-white border-secondary" placeholder="flag{...}" id="flag-${ch.id}">
                            <button class="btn btn-warning" onclick="submitFlagV2(${ch.id})">Submit</button>
                        </div>
                        ${ch.files_url ? `<a href="${ch.files_url}" class="btn btn-sm btn-outline-light w-100"><i class="fas fa-download me-2"></i>Download Files</a>` : ''}
                    </div>
                </div>
            </div>
        </div>`;
    });

    html += `</div></div>`;
    container.innerHTML = html;
}

window.submitFlagV2 = function (id) {
    const input = document.getElementById(`flag-${id}`);
    const flag = input.value;

    // Simulate check (In real app, POST to /api/submit-flag)
    if (flag.startsWith('flag{')) {
        alert('🎉 Correct Flag! (Simulation)');
        input.classList.add('is-valid');
    } else {
        alert('❌ Incorrect Flag');
        input.classList.add('is-invalid');
    }
}

// ==================== GLOBAL LEADERBOARD ====================

// ==================== GLOBAL LEADERBOARD ====================

function pageLeaderboard() {
    // Initialize the advanced Scoreboard system
    setTimeout(() => {
        if (typeof Scoreboard !== 'undefined') {
            Scoreboard.init();
        } else {
            console.error('Scoreboard.js not loaded!');
        }
    }, 100);

    return `<div id="scoreboard-container" class="fade-in" style="min-height: 500px;">
                <div class="text-center mt-5">
                    <i class="fas fa-circle-notch fa-spin fa-3x text-warning"></i>
                    <p class="mt-3 text-white-50">Loading BreachLabs Leaderboard...</p>
                </div>
            </div>`;
}


// Wrapper for app.js loadPage compatibility
window.pageCourseViewer = function (courseId) {
    setTimeout(() => renderCourseDetail(courseId), 0);
    return `<div class='text-center mt-5'><i class='fas fa-circle-notch fa-spin fa-3x text-success'></i></div>`;
};
