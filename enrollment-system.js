/* ============================================================
   ENROLLMENT SYSTEM - Study Hub Platform
   Handles path enrollment, access control, and progress tracking
   ============================================================ */

const EnrollmentSystem = {
    // Cache for enrollment data
    enrolledPaths: new Map(),

    // API Base URL
    apiBase: 'http://localhost:5000/api',

    // ==================== INITIALIZATION ====================

    async init() {
        // Always load from localStorage first
        this.loadFromLocalStorage();

        const userId = this.getCurrentUserId();
        if (userId) {
            await this.loadUserEnrollments(userId);
        }
    },

    getCurrentUserId() {
        // Try sessionStorage first
        const sessionUser = JSON.parse(sessionStorage.getItem('user') || '{}');
        if (sessionUser.id) return sessionUser.id;
        if (sessionUser.email) return sessionUser.email;
        if (sessionUser.username) return sessionUser.username;

        // Try localStorage
        const localUser = JSON.parse(localStorage.getItem('user') || '{}');
        if (localUser.id) return localUser.id;
        if (localUser.email) return localUser.email;
        if (localUser.username) return localUser.username;

        // Check if logged in via isLoggedIn flag
        const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true' ||
            sessionStorage.getItem('isLoggedIn') === 'true';
        if (isLoggedIn) return 'logged_user';

        return null;
    },

    // ==================== ENROLLMENT API CALLS ====================

    async loadUserEnrollments(userId) {
        try {
            const response = await fetch(`${this.apiBase}/user/${userId}/enrolled-paths`);
            const data = await response.json();

            if (data.success) {
                data.enrollments.forEach(e => {
                    this.enrolledPaths.set(String(e.path_id), e);
                });
            }
            return data;
        } catch (error) {
            console.error('Failed to load enrollments:', error);
            // Fallback to localStorage for offline support
            this.loadFromLocalStorage();
            return { success: false, error: error.message };
        }
    },

    async enrollInPath(pathId) {
        // Check if user is logged in
        const isLoggedIn = this.checkUserLoggedIn();

        if (!isLoggedIn) {
            this.showLoginRequiredPopup(pathId);
            return { success: false, error: 'Login required' };
        }

        // Check if path is premium
        const pathData = this.getPathData(pathId);
        const isPremium = pathData?.premium === true;

        // Check if user has premium subscription
        const userHasPremium = this.checkUserPremium();

        if (isPremium && !userHasPremium) {
            // Redirect to subscription page
            this.showPremiumRequired(pathId, pathData?.name);
            return { success: false, error: 'Premium required' };
        }

        // Enroll locally (skip API for now)
        this.enrollLocally(pathId);
        localStorage.setItem('breachlabs_last_enrolled', pathId);
        return { success: true, message: 'Enrolled successfully!' };
    },

    // Check if user is logged in
    checkUserLoggedIn() {
        // Check AuthState first
        if (typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn()) {
            return true;
        }

        // Check localStorage/sessionStorage flags
        if (localStorage.getItem('isLoggedIn') === 'true' ||
            sessionStorage.getItem('isLoggedIn') === 'true') {
            return true;
        }

        // Check for user object in storage
        const sessionUser = sessionStorage.getItem('user');
        const localUser = localStorage.getItem('user');
        if (sessionUser || localUser) {
            try {
                const user = JSON.parse(sessionUser || localUser);
                if (user && (user.id || user.email || user.username)) {
                    return true;
                }
            } catch (e) { }
        }

        return false;
    },

    // Helper for bilingual text (uses global txt function if available)
    _txt(ar, en) {
        if (typeof txt === 'function') {
            return txt(ar, en);
        }
        // Fallback: check currentLang global
        if (typeof currentLang !== 'undefined' && currentLang === 'ar') {
            return ar;
        }
        return en;
    },

    // Show beautiful login required popup
    showLoginRequiredPopup(pathId) {
        const pathData = this.getPathData(pathId);
        const pathName = pathData?.name || 'Learning Path';
        const t = this._txt.bind(this);

        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'loginRequiredModal';
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; border: none; border-radius: 20px; overflow: hidden;">
                    <div class="modal-header border-0" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 25px;">
                        <h5 class="modal-title" style="font-size: 1.3rem;">
                            <i class="fa-solid fa-user-lock me-2"></i>
                            ${t('تسجيل الدخول مطلوب', 'Login Required')}
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center py-5">
                        <div class="mb-4">
                            <div style="width: 100px; height: 100px; margin: 0 auto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                                <i class="fa-solid fa-user-plus" style="font-size: 2.5rem; color: white;"></i>
                            </div>
                        </div>
                        <h4 class="mb-3" style="color: #e2e8f0;">${pathName}</h4>
                        <p class="mb-4" style="color: #94a3b8; font-size: 1.1rem; line-height: 1.7;">
                            ${t('للتسجيل في هذا المسار وبدء التعلم، يجب عليك تسجيل الدخول أولاً', 'To enroll in this path and start learning, you need to log in first')}
                        </p>
                        <div class="d-flex justify-content-center gap-4 mb-4">
                            <div class="text-center">
                                <div style="width: 50px; height: 50px; background: rgba(102, 126, 234, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin: 0 auto 8px;">
                                    <i class="fas fa-chart-line" style="color: #667eea; font-size: 1.3rem;"></i>
                                </div>
                                <div style="font-size: 12px; color: #94a3b8;">${t('تتبع التقدم', 'Track Progress')}</div>
                            </div>
                            <div class="text-center">
                                <div style="width: 50px; height: 50px; background: rgba(16, 185, 129, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin: 0 auto 8px;">
                                    <i class="fas fa-certificate" style="color: #10b981; font-size: 1.3rem;"></i>
                                </div>
                                <div style="font-size: 12px; color: #94a3b8;">${t('شهادة إتمام', 'Completion Certificate')}</div>
                            </div>
                            <div class="text-center">
                                <div style="width: 50px; height: 50px; background: rgba(245, 158, 11, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin: 0 auto 8px;">
                                    <i class="fas fa-bookmark" style="color: #f59e0b; font-size: 1.3rem;"></i>
                                </div>
                                <div style="font-size: 12px; color: #94a3b8;">${t('حفظ التقدم', 'Save Progress')}</div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer border-0 justify-content-center gap-3 pb-4" style="background: rgba(0,0,0,0.2);">
                        <button type="button" class="btn btn-outline-light px-4 py-2" data-bs-dismiss="modal">
                            <i class="fa-solid fa-times me-1"></i> ${t('لاحقاً', 'Later')}
                        </button>
                        <button type="button" class="btn px-4 py-2" id="btnGoToLogin" 
                                style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-weight: 600;">
                            <i class="fa-solid fa-sign-in-alt me-1"></i> ${t('تسجيل الدخول', 'Log In')}
                        </button>
                        <button type="button" class="btn px-4 py-2" id="btnGoToRegister" 
                                style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; border: none; border-radius: 8px; font-weight: 600;">
                            <i class="fa-solid fa-user-plus me-1"></i> ${t('إنشاء حساب', 'Sign Up')}
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);

        // Handle login button
        modal.querySelector('#btnGoToLogin').onclick = () => {
            bsModal.hide();
            // Store the path ID to redirect back after login
            sessionStorage.setItem('pendingEnrollPath', pathId);
            if (typeof loadPage === 'function') {
                loadPage('profile'); // Or 'login' if you have a dedicated login page
            } else {
                window.location.href = '#login';
            }
        };


        // Handle register button
        modal.querySelector('#btnGoToRegister').onclick = () => {
            bsModal.hide();
            sessionStorage.setItem('pendingEnrollPath', pathId);
            if (typeof loadPage === 'function') {
                loadPage('register');
            } else {
                window.location.href = '#register';
            }
        };

        // Cleanup on hide
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
        });

        bsModal.show();
    },

    // Get path data from UnifiedLearningData
    getPathData(pathId) {
        if (typeof UnifiedLearningData !== 'undefined') {
            return UnifiedLearningData.paths?.find(p => p.id === pathId) || null;
        }
        return null;
    },

    // Check if user has premium subscription
    checkUserPremium() {
        const user = JSON.parse(sessionStorage.getItem('user') || '{}');
        return user.premium === true || user.subscription === 'premium' || user.subscribed === true;
    },

    // Show premium required popup
    showPremiumRequired(pathId, pathName) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'premiumModal';
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; border: none; border-radius: 20px;">
                    <div class="modal-header border-0">
                        <h5 class="modal-title">
                            <i class="fa-solid fa-crown text-warning me-2"></i>
                            Premium Content
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center py-4">
                        <div class="mb-4">
                            <i class="fa-solid fa-lock" style="font-size: 4rem; color: #f59e0b;"></i>
                        </div>
                        <h4 class="mb-3">${pathName || 'Premium Path'}</h4>
                        <p class="text-muted mb-4">
                            هذا المسار متاح فقط للأعضاء المميزين. اشترك الآن للوصول لجميع المحتوى!
                        </p>
                        <div class="d-flex justify-content-center gap-3 mb-3">
                            <div class="text-center px-3">
                                <i class="fas fa-infinity text-warning mb-2" style="font-size: 24px;"></i>
                                <div style="font-size: 12px;">وصول غير محدود</div>
                            </div>
                            <div class="text-center px-3">
                                <i class="fas fa-certificate text-warning mb-2" style="font-size: 24px;"></i>
                                <div style="font-size: 12px;">شهادات معتمدة</div>
                            </div>
                            <div class="text-center px-3">
                                <i class="fas fa-server text-warning mb-2" style="font-size: 24px;"></i>
                                <div style="font-size: 12px;">معامل متقدمة</div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer border-0 justify-content-center gap-3 pb-4">
                        <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">
                            <i class="fa-solid fa-times me-1"></i> Later
                        </button>
                        <button type="button" class="btn px-4" id="btnSubscribe" 
                                style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; border: none;">
                            <i class="fa-solid fa-crown me-1"></i> Subscribe Now
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);

        // Handle subscribe button
        modal.querySelector('#btnSubscribe').onclick = () => {
            bsModal.hide();
            if (typeof loadPage === 'function') {
                loadPage('subscription');
            }
        };

        // Cleanup on hide
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
        });

        bsModal.show();
    },


    async unenrollFromPath(pathId) {
        const userId = this.getCurrentUserId();

        if (!userId) return { success: false, error: 'Login required' };

        try {
            const response = await fetch(`${this.apiBase}/path/${pathId}/unenroll`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });

            const data = await response.json();

            if (data.success) {
                this.enrolledPaths.delete(String(pathId));
                this.saveToLocalStorage();
            }

            return data;
        } catch (error) {
            console.error('Unenroll failed:', error);
            this.enrolledPaths.delete(String(pathId));
            this.saveToLocalStorage();
            return { success: true };
        }
    },

    async updateProgress(pathId, progress, modulesCompleted = 0) {
        const userId = this.getCurrentUserId();
        if (!userId) return;

        try {
            await fetch(`${this.apiBase}/path/${pathId}/progress`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: userId,
                    progress_percentage: progress,
                    modules_completed: modulesCompleted
                })
            });

            // Update local cache
            const enrollment = this.enrolledPaths.get(String(pathId));
            if (enrollment) {
                enrollment.progress_percentage = progress;
                enrollment.modules_completed = modulesCompleted;
                this.saveToLocalStorage();
            }
        } catch (error) {
            console.error('Progress update failed:', error);
        }
    },

    // ==================== ENROLLMENT CHECK ====================

    isEnrolled(pathId) {
        // If user is not logged in, don't show any paths as enrolled
        if (!this.checkUserLoggedIn()) {
            return false;
        }

        // Check if this path is the currently active enrollment
        const activePath = localStorage.getItem('breachlabs_active_path');
        return activePath === String(pathId);
    },

    getEnrollment(pathId) {
        // If user is not logged in, don't show enrollment data
        if (!this.checkUserLoggedIn()) {
            return null;
        }
        return this.enrolledPaths.get(String(pathId)) || null;
    },

    getProgress(pathId) {
        // If user is not logged in, always show 0 progress
        if (!this.checkUserLoggedIn()) {
            return 0;
        }
        const enrollment = this.getEnrollment(pathId);
        return enrollment ? enrollment.progress_percentage || 0 : 0;
    },

    // ==================== LOCAL STORAGE ====================

    saveToLocalStorage() {
        const paths = Array.from(this.enrolledPaths.values());
        localStorage.setItem('enrolledPaths', JSON.stringify(paths));
    },

    loadFromLocalStorage() {
        try {
            const stored = localStorage.getItem('enrolledPaths');
            if (stored) {
                const paths = JSON.parse(stored);
                paths.forEach(p => {
                    this.enrolledPaths.set(String(p.path_id), p);
                });
            }
        } catch (e) {
            console.error('Failed to load from localStorage:', e);
        }
    },

    enrollLocally(pathId) {
        // Clear all existing enrollments (single path enrollment system)
        this.enrolledPaths.clear();

        // Create new enrollment
        const enrollment = {
            path_id: pathId,
            enrolled_at: new Date().toISOString(),
            progress_percentage: 0,
            modules_completed: 0
        };
        this.enrolledPaths.set(String(pathId), enrollment);

        // Store the currently active path ID
        localStorage.setItem('breachlabs_active_path', pathId);

        this.saveToLocalStorage();
    },

    // Get currently active enrolled path
    getActiveEnrollment() {
        return localStorage.getItem('breachlabs_active_path') || null;
    },

    // ==================== UI COMPONENTS ====================

    showEnrollmentPopup(pathId, pathName) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'enrollmentModal';
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; border: none; border-radius: 20px;">
                    <div class="modal-header border-0">
                        <h5 class="modal-title">
                            <i class="fa-solid fa-lock text-warning me-2"></i>
                            Enrollment Required
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center py-4">
                        <div class="mb-4">
                            <i class="fa-solid fa-graduation-cap" style="font-size: 4rem; color: #667eea;"></i>
                        </div>
                        <h4 class="mb-3">${pathName || 'This Path'}</h4>
                        <p class="text-muted mb-4">
                            يجب عليك التسجيل في هذا المسار أولاً لبدء التعلم وتشغيل المعامل.
                        </p>
                        <p class="small text-muted">
                            <i class="fa-solid fa-info-circle me-1"></i>
                            التسجيل مجاني ويتيح لك تتبع تقدمك والحصول على شهادة عند الإتمام.
                        </p>
                    </div>
                    <div class="modal-footer border-0 justify-content-center gap-3 pb-4">
                        <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">
                            <i class="fa-solid fa-times me-1"></i> Later
                        </button>
                        <button type="button" class="btn px-4" id="btnEnrollNow" 
                                style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none;">
                            <i class="fa-solid fa-rocket me-1"></i> Enroll Now
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);

        // Handle enroll button
        modal.querySelector('#btnEnrollNow').onclick = async () => {
            const result = await this.enrollInPath(pathId);
            bsModal.hide();

            if (result.success) {
                // Refresh the page to show unlocked content
                if (typeof loadPage === 'function') {
                    loadPage('learningpaths');
                } else {
                    location.reload();
                }
            }
        };

        // Cleanup on hide
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
        });

        bsModal.show();
    },

    showEnrollmentSuccess(pathId) {
        if (typeof showToast === 'function') {
            showToast('🎉 تم التسجيل بنجاح!', 'success');
        }
    },

    showLoginRequired() {
        if (typeof showToast === 'function') {
            showToast('يرجى تسجيل الدخول أولاً', 'warning');
        }
        // Optionally redirect to login
        if (typeof loadPage === 'function') {
            loadPage('profile');
        }
    },

    // ==================== ROOM ACCESS CHECK ====================

    checkRoomAccess(pathId, roomId, callback) {
        if (this.isEnrolled(pathId)) {
            // Allow access
            if (callback) callback(true);
            return true;
        } else {
            // Show enrollment popup
            const pathName = this.getPathName(pathId);
            this.showEnrollmentPopup(pathId, pathName);
            if (callback) callback(false);
            return false;
        }
    },

    getPathName(pathId) {
        // Try to get from UnifiedLearningData if available
        if (typeof UnifiedLearningData !== 'undefined') {
            const path = UnifiedLearningData.paths?.find(p => p.id === pathId);
            if (path) return path.name;
        }
        return 'Learning Path';
    },

    // ==================== UI HELPERS ====================

    getEnrollButtonHTML(pathId, isEnrolled = false, progress = 0) {
        if (isEnrolled) {
            return `
                <button class="btn btn-lg px-5 py-3" onclick="EnrollmentSystem.resumeLearning('${pathId}')"
                        style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; border: none; border-radius: 50px; font-weight: bold;">
                    <i class="fa-solid fa-play me-2"></i>
                    ${progress > 0 ? 'Resume Learning' : 'Start Learning'}
                    ${progress > 0 ? `<span class="badge bg-white text-success ms-2">${progress}%</span>` : ''}
                </button>
            `;
        } else {
            return `
                <button class="btn btn-lg px-5 py-3" onclick="EnrollmentSystem.enrollInPath('${pathId}')"
                        style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 50px; font-weight: bold;">
                    <i class="fa-solid fa-rocket me-2"></i>
                    Enroll in Path
                </button>
            `;
        }
    },

    getLockIconHTML(isLocked = true) {
        if (isLocked) {
            return `<span class="badge bg-secondary"><i class="fa-solid fa-lock"></i></span>`;
        } else {
            return `<span class="badge bg-success"><i class="fa-solid fa-unlock"></i></span>`;
        }
    },

    resumeLearning(pathId) {
        // Navigate to path page or last active room
        if (typeof loadPage === 'function') {
            loadPage('learningpaths', { pathId: pathId });
        }
    },

    // ==================== PROGRESS CIRCLE ====================

    getProgressCircleHTML(progress) {
        const circumference = 2 * Math.PI * 40; // r=40
        const strokeDashoffset = circumference - (progress / 100) * circumference;

        return `
            <svg width="100" height="100" class="progress-circle">
                <circle cx="50" cy="50" r="40" stroke="#2a2a3d" stroke-width="8" fill="none"/>
                <circle cx="50" cy="50" r="40" stroke="#10b981" stroke-width="8" fill="none"
                        stroke-dasharray="${circumference}" 
                        stroke-dashoffset="${strokeDashoffset}"
                        stroke-linecap="round"
                        transform="rotate(-90 50 50)"
                        style="transition: stroke-dashoffset 0.5s ease;"/>
                <text x="50" y="55" text-anchor="middle" fill="white" font-size="18" font-weight="bold">
                    ${progress}%
                </text>
            </svg>
        `;
    }
};

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    EnrollmentSystem.init();
});

// IMMEDIATE: Load from localStorage NOW so isEnrolled works immediately
(function () {
    try {
        const stored = localStorage.getItem('enrolledPaths');
        if (stored) {
            const paths = JSON.parse(stored);
            paths.forEach(p => {
                EnrollmentSystem.enrolledPaths.set(String(p.path_id), p);
            });
            console.log('EnrollmentSystem: Loaded', paths.length, 'enrolled paths from localStorage');
        }
    } catch (e) {
        console.error('EnrollmentSystem: Failed to load from localStorage:', e);
    }
})();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EnrollmentSystem;
}
