/* ============================================================
   SKILL TREE - Interactive Learning Path Component
   Cyberpunk-style skill tree for cybersecurity platform
   ============================================================ */

// Skill Tree Configuration
const skillTreeConfig = {
    domains: [
        {
            id: 'red-team',
            name: 'Red Team',
            nameAr: 'الفريق الأحمر',
            icon: '💀',
            description: 'Offensive Security & Penetration Testing',
            descriptionAr: 'الأمن الهجومي واختبار الاختراق',
            pathsCount: 6,
            color: '#ff0055'
        },
        {
            id: 'blue-team',
            name: 'Blue Team',
            nameAr: 'الفريق الأزرق',
            icon: '🛡️',
            description: 'Defensive Security & Incident Response',
            descriptionAr: 'الأمن الدفاعي والاستجابة للحوادث',
            pathsCount: 6,
            color: '#00d4ff'
        },
        {
            id: 'ctf',
            name: 'CTF Arena',
            nameAr: 'ساحة CTF',
            icon: '🏆',
            description: 'Competitive Hacking Challenges',
            descriptionAr: 'تحديات الاختراق التنافسية',
            pathsCount: 3,
            color: '#ff6600'
        }
    ]
};

// Get paths for a domain from platformData
function getSkillTreePaths(domainId) {
    if (typeof platformData === 'undefined') return [];

    const paths = Object.values(platformData.paths).filter(p => p.domainId === domainId);

    // Add status based on user progress
    const progress = JSON.parse(localStorage.getItem('pathProgress') || '{}');
    const moduleProgress = JSON.parse(localStorage.getItem('moduleProgress') || '{}');

    return paths.map((path, index) => {
        const pathProgress = progress[path.id] || {};
        const modules = path.modules || [];

        // Calculate completion percentage
        let completedModules = 0;
        modules.forEach(m => {
            const key = `${path.id}_${m.id}`;
            if (moduleProgress[key]?.completed) completedModules++;
        });

        const progressPercent = modules.length > 0
            ? Math.round((completedModules / modules.length) * 100)
            : 0;

        // Determine status
        let status = 'locked';
        if (index === 0 || progressPercent > 0) {
            status = progressPercent === 100 ? 'completed' :
                progressPercent > 0 ? 'in-progress' : 'available';
        }

        // Check prerequisites
        const prereqs = path.prerequisites || [];
        const prereqsMet = prereqs.every(prereqId => {
            const prereqProgress = progress[prereqId];
            return prereqProgress?.completed;
        });

        if (prereqs.length > 0 && !prereqsMet && status === 'locked') {
            status = 'locked';
        } else if (prereqs.length === 0 || prereqsMet) {
            if (status === 'locked') status = 'available';
        }

        return {
            ...path,
            status,
            progressPercent,
            completedModules,
            totalModules: modules.length,
            prerequisites: prereqs
        };
    });
}

// Render the Skill Tree page
function pageSkillTree() {
    const isArabic = document.documentElement.lang === 'ar';

    return `
    <div class="skill-tree-container">
        <!-- Header -->
        <div class="skill-tree-header">
            <h1 class="skill-tree-title">${isArabic ? 'شجرة المهارات' : 'SKILL TREE'}</h1>
            <p class="skill-tree-subtitle">${isArabic ? 'اختر مسارك وابدأ رحلتك' : 'Choose your path and begin your journey'}</p>
        </div>
        
        <!-- Domain Selector -->
        <div class="domain-selector">
            ${skillTreeConfig.domains.map(domain => `
                <div class="domain-card ${domain.id}" 
                     onclick="selectSkillDomain('${domain.id}')"
                     data-domain="${domain.id}">
                    <div class="domain-icon">${domain.icon}</div>
                    <h3 class="domain-name">${isArabic ? domain.nameAr : domain.name}</h3>
                    <p class="domain-desc">${isArabic ? domain.descriptionAr : domain.description}</p>
                    <span class="domain-paths-count">
                        <i class="fa-solid fa-route"></i> 
                        ${domain.pathsCount} ${isArabic ? 'مسارات' : 'Paths'}
                    </span>
                </div>
            `).join('')}
        </div>
        
        <!-- Skill Trees for each domain -->
        <div class="skill-tree-graph">
            ${skillTreeConfig.domains.map(domain => `
                <div class="tree-container" id="tree-${domain.id}" data-domain="${domain.id}">
                    <div class="tree-header" style="color: ${domain.color};">
                        <span class="tree-header-icon">${domain.icon}</span>
                        <h2 class="tree-header-title">${isArabic ? domain.nameAr : domain.name}</h2>
                    </div>
                    <div class="skill-nodes-wrapper">
                        <svg class="connections-svg" id="svg-${domain.id}"></svg>
                        <div class="skill-nodes-grid" id="nodes-${domain.id}">
                            <!-- Nodes will be dynamically inserted -->
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
        
        <!-- Tooltip -->
        <div class="skill-tooltip" id="skill-tooltip"></div>
    </div>
    `;
}

// Select a domain and show its skill tree
window.selectSkillDomain = function (domainId) {
    // Update active domain card
    document.querySelectorAll('.domain-card').forEach(card => {
        card.classList.toggle('active', card.dataset.domain === domainId);
    });

    // Show/hide tree containers
    document.querySelectorAll('.tree-container').forEach(container => {
        container.classList.toggle('active', container.dataset.domain === domainId);
    });

    // Render nodes for this domain
    renderSkillNodes(domainId);
};

// Render skill nodes for a domain
function renderSkillNodes(domainId) {
    const nodesContainer = document.getElementById(`nodes-${domainId}`);
    const svgContainer = document.getElementById(`svg-${domainId}`);

    if (!nodesContainer) return;

    const paths = getSkillTreePaths(domainId);
    const isArabic = document.documentElement.lang === 'ar';

    // Render nodes
    nodesContainer.innerHTML = paths.map((path, index) => {
        const difficultyClass = `difficulty-${path.difficulty || 'beginner'}`;
        const statusClass = path.status;

        return `
        <div class="skill-node ${statusClass}" 
             data-path-id="${path.id}"
             data-index="${index}"
             onmouseenter="showSkillTooltip(event, '${path.id}')"
             onmouseleave="hideSkillTooltip()"
             onclick="openSkillPath('${path.id}', '${path.status}')">
            
            ${path.status === 'locked' ? '<div class="node-lock"><i class="fa-solid fa-lock"></i></div>' : ''}
            
            <div class="node-header">
                <span class="node-icon" style="color: ${path.color};">
                    <i class="fa-solid ${path.icon}"></i>
                </span>
                <h4 class="node-title">${isArabic ? path.nameAr : path.name}</h4>
            </div>
            
            <div class="node-meta">
                <span class="node-badge ${difficultyClass}">
                    ${path.difficulty || 'Beginner'}
                </span>
                <span class="node-badge modules">
                    <i class="fa-solid fa-book"></i> ${path.totalModules || (path.modules?.length || 0)}
                </span>
            </div>
            
            ${path.status !== 'locked' ? `
                <div class="node-progress">
                    <div class="node-progress-bar" style="width: ${path.progressPercent}%"></div>
                </div>
                <button class="skill-node-cta">
                    ${path.status === 'completed' ? '<i class="fa-solid fa-eye"></i> Review' :
                    path.status === 'in-progress' ? '<i class="fa-solid fa-play"></i> Continue' :
                        '<i class="fa-solid fa-rocket"></i> Start'}
                </button>
            ` : ''}
        </div>
        `;
    }).join('');

    // Draw connections after nodes are rendered
    setTimeout(() => drawConnections(domainId, paths), 100);
}

// Draw SVG connections between nodes
function drawConnections(domainId, paths) {
    const svgContainer = document.getElementById(`svg-${domainId}`);
    const nodesContainer = document.getElementById(`nodes-${domainId}`);

    if (!svgContainer || !nodesContainer) return;

    const nodes = nodesContainer.querySelectorAll('.skill-node');
    if (nodes.length < 2) return;

    // Get container dimensions
    const containerRect = nodesContainer.getBoundingClientRect();
    svgContainer.setAttribute('width', containerRect.width);
    svgContainer.setAttribute('height', containerRect.height);

    let svgContent = '';

    // Create connections based on prerequisites
    paths.forEach((path, index) => {
        if (path.prerequisites && path.prerequisites.length > 0) {
            path.prerequisites.forEach(prereqId => {
                const prereqIndex = paths.findIndex(p => p.id === prereqId);
                if (prereqIndex >= 0) {
                    const fromNode = nodes[prereqIndex];
                    const toNode = nodes[index];
                    const fromPath = paths[prereqIndex];

                    if (fromNode && toNode) {
                        const fromRect = fromNode.getBoundingClientRect();
                        const toRect = toNode.getBoundingClientRect();

                        const x1 = fromRect.left + fromRect.width - containerRect.left;
                        const y1 = fromRect.top + fromRect.height / 2 - containerRect.top;
                        const x2 = toRect.left - containerRect.left;
                        const y2 = toRect.top + toRect.height / 2 - containerRect.top;

                        const isLocked = path.status === 'locked';
                        const isCompleted = fromPath.status === 'completed';

                        // Draw curved line with glow if completed
                        const midX = (x1 + x2) / 2;
                        svgContent += `
                            <path class="connection-line ${isLocked ? 'locked' : ''} ${isCompleted ? 'completed' : ''}" 
                                  d="M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}"/>
                        `;
                    }
                }
            });
        }


        // Connect sequential nodes if no prerequisites defined
        if (!path.prerequisites || path.prerequisites.length === 0) {
            if (index > 0) {
                const fromNode = nodes[index - 1];
                const toNode = nodes[index];

                if (fromNode && toNode) {
                    const fromRect = fromNode.getBoundingClientRect();
                    const toRect = toNode.getBoundingClientRect();

                    // Only connect if nodes are in the same row
                    if (Math.abs(fromRect.top - toRect.top) < 50) {
                        const x1 = fromRect.right - containerRect.left;
                        const y1 = fromRect.top + fromRect.height / 2 - containerRect.top;
                        const x2 = toRect.left - containerRect.left;
                        const y2 = toRect.top + toRect.height / 2 - containerRect.top;

                        const isLocked = path.status === 'locked';

                        svgContent += `
                            <path class="connection-line ${isLocked ? 'locked' : ''}" 
                                  d="M${x1},${y1} L${x2},${y2}"/>
                        `;
                    }
                }
            }
        }
    });

    svgContainer.innerHTML = svgContent;
}

// Show tooltip on hover
window.showSkillTooltip = function (event, pathId) {
    const tooltip = document.getElementById('skill-tooltip');
    if (!tooltip || typeof platformData === 'undefined') return;

    const path = platformData.paths[pathId];
    if (!path) return;

    const isArabic = document.documentElement.lang === 'ar';
    const paths = getSkillTreePaths(path.domainId);
    const pathData = paths.find(p => p.id === pathId);

    // Get prerequisites names
    let prereqsHtml = '';
    if (path.prerequisites && path.prerequisites.length > 0) {
        const prereqNames = path.prerequisites.map(id => {
            const prereq = platformData.paths[id];
            return prereq ? (isArabic ? prereq.nameAr : prereq.name) : id;
        }).join(', ');
        prereqsHtml = `
            <div class="tooltip-prereq">
                <i class="fa-solid fa-lock"></i> 
                ${isArabic ? 'المتطلبات المسبقة:' : 'Prerequisites:'} ${prereqNames}
            </div>
        `;
    }

    tooltip.innerHTML = `
        <div class="tooltip-title">
            <i class="fa-solid ${path.icon}" style="color: ${path.color}"></i>
            ${isArabic ? path.nameAr : path.name}
        </div>
        <p class="tooltip-desc">${isArabic ? path.descriptionAr : path.description}</p>
        <div class="tooltip-details">
            <span class="tooltip-detail">
                <i class="fa-solid fa-clock"></i> ${path.estimatedHours || 40}h
            </span>
            <span class="tooltip-detail">
                <i class="fa-solid fa-book"></i> ${path.modules?.length || 0} ${isArabic ? 'وحدات' : 'Modules'}
            </span>
            <span class="tooltip-detail">
                <i class="fa-solid fa-signal"></i> ${path.difficulty || 'Beginner'}
            </span>
            ${path.certification ? `
                <span class="tooltip-detail">
                    <i class="fa-solid fa-certificate"></i> ${path.certification}
                </span>
            ` : ''}
        </div>
        ${pathData?.status !== 'locked' && pathData?.progressPercent > 0 ? `
            <div class="tooltip-detail" style="margin-top: 10px;">
                <i class="fa-solid fa-chart-line"></i> 
                ${isArabic ? 'التقدم:' : 'Progress:'} ${pathData.progressPercent}%
            </div>
        ` : ''}
        ${prereqsHtml}
    `;

    // Position tooltip
    const rect = event.target.closest('.skill-node').getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();

    let left = rect.right + 15;
    let top = rect.top;

    // Adjust if tooltip goes off screen
    if (left + 320 > window.innerWidth) {
        left = rect.left - 335;
    }
    if (top + 250 > window.innerHeight) {
        top = window.innerHeight - 260;
    }

    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
    tooltip.classList.add('visible');
};

// Hide tooltip
window.hideSkillTooltip = function () {
    const tooltip = document.getElementById('skill-tooltip');
    if (tooltip) {
        tooltip.classList.remove('visible');
    }
};

// Open a skill path
window.openSkillPath = function (pathId, status) {
    if (status === 'locked') {
        showToast(txt('هذا المسار مغلق! أكمل المتطلبات المسبقة أولاً.', 'This path is locked! Complete prerequisites first.'), 'error');
        return;
    }

    // Navigate to path roadmap
    if (typeof loadPage === 'function') {
        loadPage('path-roadmap', pathId);
    }
};

// Initialize skill tree when page loads
function initSkillTree() {
    // Auto-select first domain after a short delay
    setTimeout(() => {
        selectSkillDomain('red-team');
    }, 300);

    // Redraw connections on window resize
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            const activeTree = document.querySelector('.tree-container.active');
            if (activeTree) {
                const domainId = activeTree.dataset.domain;
                const paths = getSkillTreePaths(domainId);
                drawConnections(domainId, paths);
            }
        }, 250);
    });
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { pageSkillTree, initSkillTree };
}
