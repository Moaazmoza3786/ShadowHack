/* career-track-detail.js - Career Track Detail Page UI */

(function () {
    // Inject styles
    const styles = document.createElement('style');
    styles.textContent = `
        /* Career Track Detail Page Styles */
        .career-track-detail {
            min-height: 100vh;
            background: #0f172a;
            font-family: 'Inter', -apple-system, sans-serif;
        }

        /* Header Section */
        .ct-header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 60px 40px;
            position: relative;
            overflow: hidden;
        }

        .ct-header::before {
            content: '';
            position: absolute;
            top: 0; right: 0;
            width: 400px; height: 400px;
            background: radial-gradient(circle, rgba(132, 204, 22, 0.1), transparent 70%);
            pointer-events: none;
        }

        .ct-header-content {
            display: flex;
            gap: 60px;
            max-width: 1200px;
            margin: 0 auto;
            align-items: center;
        }

        .ct-header-left {
            flex: 1;
        }

        .ct-header-right {
            flex: 0 0 300px;
            display: flex;
            justify-content: center;
        }

        .ct-badge {
            display: inline-block;
            background: #1e3a8a;
            color: #60a5fa;
            padding: 6px 14px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 16px;
        }

        .ct-title {
            font-size: 2.5rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 16px;
            line-height: 1.2;
        }

        .ct-meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 24px;
        }

        .ct-meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #94a3b8;
            font-size: 0.9rem;
        }

        .ct-meta-item i {
            color: #84cc16;
        }

        /* Progress Bar */
        .ct-progress {
            margin-bottom: 24px;
        }

        .ct-progress-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.85rem;
            color: #94a3b8;
        }

        .ct-progress-label span:last-child {
            color: #84cc16;
        }

        .ct-progress-bar {
            height: 12px;
            background: #1e293b;
            border-radius: 6px;
            overflow: hidden;
            position: relative;
        }

        .ct-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #84cc16, #22c55e);
            border-radius: 6px;
            transition: width 0.5s ease;
        }

        /* Dashed progress bar style */
        .ct-progress-bar.dashed {
            background: repeating-linear-gradient(
                90deg,
                #1e293b 0px,
                #1e293b 4px,
                #334155 4px,
                #334155 8px
            );
        }

        /* Enroll Button */
        .ct-enroll-btn {
            background: #84cc16;
            color: #0f172a;
            border: none;
            padding: 14px 36px;
            font-size: 1rem;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .ct-enroll-btn:hover {
            background: #a3e635;
            transform: translateY(-2px);
        }

        .ct-enroll-btn.enrolled {
            background: #22c55e;
        }

        /* Header Icon */
        .ct-header-icon {
            width: 200px;
            height: 200px;
            background: linear-gradient(135deg, #1e293b, #334155);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid #334155;
        }

        .ct-header-icon i {
            font-size: 80px;
            color: #84cc16;
        }

        /* Path Includes Section */
        .ct-includes {
            background: #1e293b;
            padding: 30px 40px;
            border-bottom: 1px solid #334155;
        }

        .ct-includes-inner {
            max-width: 1200px;
            margin: 0 auto;
        }

        .ct-includes-title {
            color: #94a3b8;
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .ct-includes-grid {
            display: flex;
            gap: 40px;
            flex-wrap: wrap;
        }

        .ct-include-item {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #e2e8f0;
            font-size: 0.9rem;
        }

        .ct-include-item i {
            color: #84cc16;
            width: 20px;
        }

        /* Description Section */
        .ct-description {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }

        .ct-section-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 20px;
        }

        .ct-description-text {
            color: #94a3b8;
            line-height: 1.8;
            font-size: 0.95rem;
            max-width: 700px;
        }

        /* Skills Section */
        .ct-skills {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 20px;
        }

        .ct-skill-tag {
            background: #334155;
            color: #e2e8f0;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85rem;
        }

        /* Modules Section */
        .ct-modules {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 40px 60px;
        }

        .ct-modules-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }

        .ct-modules-count {
            color: #94a3b8;
            font-size: 0.9rem;
        }

        .ct-modules-cost {
            color: #94a3b8;
            font-size: 0.9rem;
        }

        .ct-modules-cost span {
            color: #84cc16;
            font-weight: 600;
        }

        /* Module Card */
        .ct-module-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 20px;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .ct-module-card:hover {
            border-color: #84cc16;
            background: #1e293b;
        }

        .ct-module-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #334155, #1e293b);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .ct-module-icon i {
            font-size: 24px;
            color: #84cc16;
        }

        .ct-module-icon.offensive i {
            color: #ef4444;
        }

        .ct-module-content {
            flex: 1;
        }

        .ct-module-badges {
            display: flex;
            gap: 8px;
            margin-bottom: 8px;
            flex-wrap: wrap;
        }

        .ct-module-badge {
            font-size: 0.7rem;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .ct-module-badge.new {
            background: #22c55e;
            color: #fff;
        }

        .ct-module-badge.regular {
            background: #0d9488;
            color: #fff;
        }

        .ct-module-badge.assessment {
            background: #8b5cf6;
            color: #fff;
        }

        .ct-module-badge.offensive {
            background: #ef4444;
            color: #fff;
        }

        .ct-module-badge.defensive {
            background: #3b82f6;
            color: #fff;
        }

        .ct-module-title {
            font-size: 1rem;
            font-weight: 600;
            color: #fff;
            margin-bottom: 8px;
        }

        .ct-module-meta {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }

        .ct-module-meta-item {
            display: flex;
            align-items: center;
            gap: 6px;
            color: #64748b;
            font-size: 0.8rem;
        }

        .ct-module-meta-item i {
            color: #94a3b8;
        }

        .ct-module-action {
            color: #84cc16;
            font-size: 0.85rem;
            font-weight: 600;
            white-space: nowrap;
        }

        .ct-module-action:hover {
            text-decoration: underline;
        }

        /* Bottom CTA */
        .ct-bottom-cta {
            background: #1e293b;
            padding: 24px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-top: 1px solid #334155;
            position: sticky;
            bottom: 0;
        }

        .ct-cta-reward {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #94a3b8;
            font-size: 0.9rem;
        }

        .ct-cta-reward i {
            color: #84cc16;
        }

        .ct-cta-reward span {
            color: #84cc16;
            font-weight: 600;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .ct-header-content {
                flex-direction: column;
                text-align: center;
            }

            .ct-header-right {
                order: -1;
            }

            .ct-meta {
                justify-content: center;
            }

            .ct-includes-grid {
                justify-content: center;
            }
        }
    `;
    document.head.appendChild(styles);

    // Career Track Detail Page Component
    window.CareerTrackDetail = {
        render(trackId) {
            const track = CareerTracksData.getTrackById(trackId);
            if (!track) {
                return '<div class="error">Career Track not found</div>';
            }

            const isEnrolled = CareerTracksData.isTrackEnrolled(trackId);
            const progress = CareerTracksData.getTrackProgress(trackId);
            const totalRooms = track.modules.reduce((acc, m) => acc + (m.rooms ? m.rooms.length : 0), 0);
            const totalCubes = track.pathIncludes.cubes;

            return `
                <div class="career-track-detail">
                    <!-- Header -->
                    <div class="ct-header">
                        <div class="ct-header-content">
                            <div class="ct-header-left">
                                <span class="ct-badge">JOB ROLE PATH</span>
                                <h1 class="ct-title">${track.title}</h1>
                                <div class="ct-meta">
                                    <div class="ct-meta-item">
                                        <i class="fa-solid fa-signal"></i>
                                        <span>${track.difficulty}</span>
                                    </div>
                                    <div class="ct-meta-item">
                                        <i class="fa-regular fa-clock"></i>
                                        <span>${track.duration}</span>
                                    </div>
                                    <div class="ct-meta-item">
                                        <i class="fa-regular fa-folder"></i>
                                        <span>${track.modules.length} Modules</span>
                                    </div>
                                </div>

                                <div class="ct-progress">
                                    <div class="ct-progress-label">
                                        <span>Path Progress</span>
                                        <span>${progress.completed || 0}% Completed</span>
                                    </div>
                                    <div class="ct-progress-bar dashed">
                                        <div class="ct-progress-fill" style="width: ${progress.completed || 0}%"></div>
                                    </div>
                                </div>

                                <button class="ct-enroll-btn ${isEnrolled ? 'enrolled' : ''}" onclick="CareerTrackDetail.enroll('${trackId}')">
                                    ${isEnrolled ? 'Continue Path' : 'Enroll Path'}
                                </button>
                            </div>

                            <div class="ct-header-right">
                                <div class="ct-header-icon">
                                    <i class="fa-solid ${track.icon}"></i>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Path Includes -->
                    <div class="ct-includes">
                        <div class="ct-includes-inner">
                            <div class="ct-includes-title">Path Includes</div>
                            <div class="ct-includes-grid">
                                <div class="ct-include-item">
                                    <i class="fa-regular fa-folder"></i>
                                    <span>${track.pathIncludes.modules} Modules</span>
                                </div>
                                <div class="ct-include-item">
                                    <i class="fa-solid fa-hand-pointer"></i>
                                    <span>${track.pathIncludes.interactiveSections} Interactive Sections</span>
                                </div>
                                <div class="ct-include-item">
                                    <i class="fa-regular fa-file-lines"></i>
                                    <span>${track.pathIncludes.assessments} Assessment(s)</span>
                                </div>
                                <div class="ct-include-item">
                                    <i class="fa-solid fa-medal"></i>
                                    <span>Badge of Completion</span>
                                </div>
                                <div class="ct-include-item">
                                    <i class="fa-solid fa-cube"></i>
                                    <span>${track.pathIncludes.cubes} Cubes</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Description -->
                    <div class="ct-description">
                        <h2 class="ct-section-title">Path Description</h2>
                        <p class="ct-description-text">${track.description}</p>

                        <div class="ct-skills">
                            ${track.skills.map(skill => `<span class="ct-skill-tag">${skill}</span>`).join('')}
                        </div>
                    </div>

                    <!-- Modules -->
                    <div class="ct-modules">
                        <div class="ct-modules-header">
                            <div>
                                <h2 class="ct-section-title" style="margin-bottom: 4px;">Modules</h2>
                                <div class="ct-modules-count">${track.modules.length} Modules · ${track.pathIncludes.assessments} Assessments</div>
                            </div>
                            <div class="ct-modules-cost">
                                Projected cost <span><i class="fa-solid fa-cube"></i> ${totalCubes}</span>
                            </div>
                        </div>

                        ${track.modules.map(module => this.renderModule(module)).join('')}
                    </div>

                    <!-- Bottom CTA -->
                    <div class="ct-bottom-cta">
                        <div class="ct-cta-reward">
                            <i class="fa-solid fa-cube"></i>
                            <span>${totalCubes} Cubes</span>
                            reward, when you complete this path
                        </div>
                        <button class="ct-enroll-btn ${isEnrolled ? 'enrolled' : ''}" onclick="CareerTrackDetail.enroll('${trackId}')">
                            ${isEnrolled ? 'Continue Path' : 'Enroll Path'}
                        </button>
                    </div>
                </div>
            `;
        },

        renderModule(module) {
            const teamClass = module.team === 'offensive' ? 'offensive' : 'defensive';
            const typeLabel = module.type === 'assessment' ? 'ASSESSMENT' : 'REGULAR';
            const teamLabel = module.team === 'offensive' ? 'OFFENSIVE' : 'DEFENSIVE';

            return `
                <div class="ct-module-card" onclick="CareerTrackDetail.openModule('${module.id}')">
                    <div class="ct-module-icon ${teamClass}">
                        <i class="fa-solid fa-${module.team === 'offensive' ? 'crosshairs' : 'shield-halved'}"></i>
                    </div>
                    <div class="ct-module-content">
                        <div class="ct-module-badges">
                            ${module.isNew ? '<span class="ct-module-badge new">New</span>' : ''}
                            <span class="ct-module-badge ${module.type}">${typeLabel}</span>
                            <span class="ct-module-badge ${teamClass}">${teamLabel}</span>
                        </div>
                        <div class="ct-module-title">${module.title}</div>
                        <div class="ct-module-meta">
                            <div class="ct-module-meta-item">
                                <i class="fa-solid fa-signal"></i>
                                <span>${module.difficulty}</span>
                            </div>
                            <div class="ct-module-meta-item">
                                <i class="fa-regular fa-clock"></i>
                                <span>${module.duration}</span>
                            </div>
                            <div class="ct-module-meta-item">
                                <i class="fa-solid fa-layer-group"></i>
                                <span>${module.tier}</span>
                            </div>
                        </div>
                    </div>
                    <span class="ct-module-action">See Module</span>
                </div>
            `;
        },

        enroll(trackId) {
            CareerTracksData.enrollInTrack(trackId);
            if (typeof showToast === 'function') {
                showToast('Successfully enrolled in career path!', 'success');
            }
            // Refresh the page
            if (typeof loadPage === 'function') {
                loadPage('career-track', { id: trackId });
            }
        },

        openModule(moduleId) {
            if (typeof showToast === 'function') {
                showToast('Opening module...', 'info');
            }
            // Navigate to module or open in room viewer
            if (typeof loadPage === 'function') {
                loadPage('module-learning', moduleId);
            }
        }
    };

    console.log('Career Track Detail component loaded');
})();
