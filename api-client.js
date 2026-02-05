/**
 * Study Hub API Client
 * Handles all communication with the backend API
 */

const API_BASE_URL = 'http://localhost:5000/api';

// ==================== AUTH STATE ====================

const AuthState = {
    token: localStorage.getItem('auth_token'),
    user: JSON.parse(localStorage.getItem('auth_user') || 'null'),

    setAuth(token, user) {
        this.token = token;
        this.user = user;
        localStorage.setItem('auth_token', token);
        localStorage.setItem('auth_user', JSON.stringify(user));

        // Dispatch custom event for UI updates
        window.dispatchEvent(new CustomEvent('authStateChanged', { detail: { user, loggedIn: true } }));
    },

    clearAuth() {
        this.token = null;
        this.user = null;
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');

        window.dispatchEvent(new CustomEvent('authStateChanged', { detail: { user: null, loggedIn: false } }));
    },

    isLoggedIn() {
        return !!this.token && !!this.user;
    },

    getUser() {
        return this.user;
    },

    getUserId() {
        return this.user?.id;
    },

    // Update user data without changing token
    updateUser(user) {
        this.user = { ...this.user, ...user };
        localStorage.setItem('auth_user', JSON.stringify(this.user));
        window.dispatchEvent(new CustomEvent('authStateChanged', { detail: { user: this.user, loggedIn: true } }));
    }
};

// Make AuthState globally available
window.AuthState = AuthState;


// ==================== API CLIENT ====================

const ApiClient = {
    /**
     * Make an API request
     */
    async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;

        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        // Add auth token if available
        if (AuthState.token) {
            config.headers['Authorization'] = `Bearer ${AuthState.token}`;
            config.headers['X-User-ID'] = AuthState.getUserId();
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            // Handle token expiration
            if (response.status === 401 && data.error === 'Token expired') {
                AuthState.clearAuth();
                showToast(txt('انتهت صلاحية الجلسة. يرجى تسجيل الدخول مرة أخرى.', 'Session expired. Please login again.'), 'warning');
                loadPage('login');
                return { success: false, error: 'Session expired' };
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            return {
                success: false,
                error: error.message || 'Network error',
                offline: !navigator.onLine
            };
        }
    },

    // GET request
    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    // POST request
    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    // PUT request
    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    // DELETE request
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
};

// Make ApiClient globally available
window.ApiClient = ApiClient;


// ==================== AUTH API ====================

const AuthAPI = {
    /**
     * Register a new user
     */
    async register(username, email, password, firstName = '', lastName = '') {
        const result = await ApiClient.post('/auth/register', {
            username,
            email,
            password,
            first_name: firstName,
            last_name: lastName
        });

        if (result.success && result.token) {
            AuthState.setAuth(result.token, result.user);
        }

        return result;
    },

    /**
     * Login user
     */
    async login(email, password) {
        const result = await ApiClient.post('/auth/login', {
            email,
            password
        });

        if (result.success && result.token) {
            AuthState.setAuth(result.token, result.user);
        }

        return result;
    },

    /**
     * Logout user
     */
    async logout() {
        // Optional: notify server
        await ApiClient.post('/auth/logout', {});
        AuthState.clearAuth();
        loadPage('login');
    },

    /**
     * Get current user profile
     */
    async getProfile() {
        return ApiClient.get('/auth/profile');
    },

    /**
     * Update user profile
     */
    async updateProfile(data) {
        const result = await ApiClient.put('/auth/profile', data);

        if (result.success && result.user) {
            AuthState.setAuth(AuthState.token, result.user);
        }

        return result;
    },

    /**
     * Change password
     */
    async changePassword(currentPassword, newPassword) {
        return ApiClient.post('/auth/change-password', {
            current_password: currentPassword,
            new_password: newPassword
        });
    },

    /**
     * Validate session on load
     */
    async validateSession() {
        if (AuthState.token) {
            try {
                // We use getProfile to validate the token. 
                // If it fails with 401, ApiClient already handles logout.
                const result = await this.getProfile();
                if (result.success && result.user) {
                    // Update local user data with fresh data from server
                    AuthState.updateUser(result.user);
                    console.log('✓ Session validated');
                }
            } catch (e) {
                console.warn('Session validation failed', e);
            }
        }
    }
};

window.AuthAPI = AuthAPI;


// ==================== PATHS API ====================

const PathsAPI = {
    /**
     * Get all learning paths
     */
    async getAll(domainId = null) {
        const endpoint = domainId ? `/paths?domain_id=${domainId}` : '/paths';
        return ApiClient.get(endpoint);
    },

    /**
     * Get path by slug
     */
    async getBySlug(slug) {
        return ApiClient.get(`/paths/${slug}`);
    },

    /**
     * Enroll in a path
     */
    async enroll(pathId) {
        return ApiClient.post(`/paths/${pathId}/enroll`, {
            user_id: AuthState.getUserId()
        });
    }
};

window.PathsAPI = PathsAPI;


// ==================== MODULES API ====================

const ModulesAPI = {
    /**
     * Get module content
     */
    async get(moduleId) {
        return ApiClient.get(`/module/${moduleId}`);
    },

    /**
     * Update module progress
     */
    async updateProgress(moduleId, progressPercentage, isCompleted = false) {
        return ApiClient.post(`/module/${moduleId}/progress`, {
            user_id: AuthState.getUserId(),
            progress_percentage: progressPercentage,
            is_completed: isCompleted
        });
    }
};

window.ModulesAPI = ModulesAPI;


// ==================== LABS API ====================

const LabsAPI = {
    /**
     * Start a lab container
     */
    async start(labId, imageName = null) {
        return ApiClient.post('/lab/start', {
            user_id: AuthState.getUserId(),
            lab_id: labId,
            image_name: imageName
        });
    },

    /**
     * Stop user's lab container
     */
    async stop() {
        return ApiClient.post('/lab/stop', {
            user_id: AuthState.getUserId()
        });
    },

    /**
     * Get current lab status
     */
    async getStatus() {
        return ApiClient.get(`/lab/status/${AuthState.getUserId()}`);
    },

    /**
     * Extend lab timeout
     */
    async extend(additionalMinutes = 60) {
        return ApiClient.post('/lab/extend', {
            user_id: AuthState.getUserId(),
            additional_minutes: additionalMinutes
        });
    },

    /**
     * Submit a flag
     */
    async submitFlag(labId, flag, hintsUsed = []) {
        return ApiClient.post('/submit-flag', {
            user_id: AuthState.getUserId(),
            lab_id: labId,
            submitted_flag: flag,
            hints_used: hintsUsed
        });
    }
};

window.LabsAPI = LabsAPI;


// ==================== QUIZ API ====================

const QuizAPI = {
    /**
     * Submit quiz answers
     */
    async submit(quizId, answers) {
        return ApiClient.post(`/quiz/${quizId}/submit`, {
            user_id: AuthState.getUserId(),
            answers: answers
        });
    }
};

window.QuizAPI = QuizAPI;


// ==================== USER API ====================

const UserAPI = {
    /**
     * Get user progress
     */
    async getProgress() {
        return ApiClient.get(`/user/${AuthState.getUserId()}/progress`);
    },

    /**
     * Get user achievements
     */
    async getAchievements() {
        return ApiClient.get(`/user/${AuthState.getUserId()}/achievements`);
    },

    /**
     * Get leaderboard
     */
    async getLeaderboard(limit = 50) {
        return ApiClient.get(`/leaderboard?limit=${limit}`);
    }
};

window.UserAPI = UserAPI;


// ==================== DOMAINS API ====================

const DomainsAPI = {
    /**
     * Get all domains with paths
     */
    async getAll() {
        return ApiClient.get('/domains');
    }
};

window.DomainsAPI = DomainsAPI;


// ==================== LEAGUES API ====================

const LeaguesAPI = {
    /**
     * Get all leagues
     */
    async getAll() {
        return ApiClient.get('/leagues');
    },

    /**
     * Get user's current league
     */
    async getCurrent() {
        return ApiClient.get('/leagues/current');
    },

    /**
     * Get leaderboard for a specific league
     */
    async getLeaderboard(leagueId) {
        return ApiClient.get(`/leagues/${leagueId}/leaderboard`);
    },

    /**
     * Join current week's league
     */
    async join() {
        return ApiClient.post('/leagues/join', {});
    },

    /**
     * Add XP (called when completing activities)
     */
    async addXP(xp) {
        return ApiClient.post('/leagues/add-xp', { xp });
    }
};

window.LeaguesAPI = LeaguesAPI;


// ==================== SUBSCRIPTION API ====================

const SubscriptionAPI = {
    /**
     * Get current subscription status
     */
    async getStatus() {
        return ApiClient.get('/subscription/status');
    },

    /**
     * Subscribe to a plan (mock payment)
     */
    async subscribe(tier, cardLastFour = '****') {
        return ApiClient.post('/subscription/subscribe', {
            tier,
            card_last_four: cardLastFour
        });
    },

    /**
     * Cancel subscription
     */
    async cancel() {
        return ApiClient.post('/subscription/cancel', {});
    },

    /**
     * Get subscription history
     */
    async getHistory() {
        return ApiClient.get('/subscription/history');
    },

    /**
     * Check if user has premium access
     */
    async checkPremium() {
        return ApiClient.get('/subscription/check-premium');
    },

    /**
     * Check if user is premium (cached version using localStorage)
     */
    isPremium() {
        const stored = localStorage.getItem('userSubscription');
        if (stored) {
            const data = JSON.parse(stored);
            if (data.expires_at && new Date(data.expires_at) > new Date()) {
                return data.tier !== 'free';
            }
        }
        return false;
    }
};

window.SubscriptionAPI = SubscriptionAPI;


// ==================== HELPER FUNCTIONS ====================

/**
 * Check if user is authenticated, redirect to login if not
 */
function requireAuth(callback) {
    if (!AuthState.isLoggedIn()) {
        showToast(txt('يرجى تسجيل الدخول أولاً', 'Please login first'), 'warning');
        loadPage('login');
        return false;
    }
    if (callback) callback();
    return true;
}
window.requireAuth = requireAuth;


/**
 * Format API errors for display
 */
function formatApiError(result) {
    if (result.offline) {
        return txt('لا يوجد اتصال بالإنترنت', 'No internet connection');
    }
    return result.error || txt('حدث خطأ غير متوقع', 'An unexpected error occurred');
}
window.formatApiError = formatApiError;


/**
 * Show loading state
 */
function showLoading(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = `
            <div class="api-loading">
                <div class="spinner"></div>
                <p>${txt('جاري التحميل...', 'Loading...')}</p>
            </div>
        `;
    }
}
window.showLoading = showLoading;


/**
 * Show error state
 */
function showError(containerId, message) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = `
            <div class="api-error">
                <i class="fa-solid fa-exclamation-triangle"></i>
                <p>${message}</p>
                <button onclick="location.reload()" class="btn btn-primary">
                    ${txt('إعادة المحاولة', 'Retry')}
                </button>
            </div>
        `;
    }
}
window.showError = showError;


// ==================== INITIALIZATION ====================

// Check auth state on load
document.addEventListener('DOMContentLoaded', () => {
    // Validate session if token exists
    AuthAPI.validateSession();

    // Update UI based on auth state
    updateAuthUI();

    // Listen for auth changes
    window.addEventListener('authStateChanged', updateAuthUI);
});

function updateAuthUI() {
    const loginBtn = document.getElementById('login-btn');
    const userMenu = document.getElementById('user-menu');
    const userAvatar = document.getElementById('user-avatar');
    const userName = document.getElementById('user-name');
    const dropdownAvatar = document.getElementById('dropdown-avatar');
    const dropdownUsername = document.getElementById('dropdown-username');
    const dropdownEmail = document.getElementById('dropdown-email');

    if (AuthState.isLoggedIn()) {
        const user = AuthState.user;
        const avatarUrl = user.avatar_url || `https://api.dicebear.com/7.x/avataaars/svg?seed=${user.username}`;

        if (loginBtn) loginBtn.style.display = 'none';
        if (userMenu) userMenu.style.display = 'flex';
        if (userAvatar) userAvatar.src = avatarUrl;
        if (userName) userName.textContent = user.username;
        if (dropdownAvatar) dropdownAvatar.src = avatarUrl;
        if (dropdownUsername) dropdownUsername.textContent = user.username;
        if (dropdownEmail) dropdownEmail.textContent = user.email || '';
    } else {
        if (loginBtn) loginBtn.style.display = 'flex';
        if (userMenu) userMenu.style.display = 'none';
    }
}
window.updateAuthUI = updateAuthUI;


// ==================== USER DROPDOWN FUNCTIONS ====================

/**
 * Toggle user dropdown menu
 */
function toggleUserDropdown() {
    const dropdown = document.getElementById('user-dropdown');
    const trigger = document.getElementById('user-menu-trigger');

    if (dropdown) {
        dropdown.classList.toggle('show');
        trigger?.classList.toggle('active');
    }
}
window.toggleUserDropdown = toggleUserDropdown;

/**
 * Close user dropdown menu
 */
function closeUserDropdown() {
    const dropdown = document.getElementById('user-dropdown');
    const trigger = document.getElementById('user-menu-trigger');

    if (dropdown) {
        dropdown.classList.remove('show');
        trigger?.classList.remove('active');
    }
}
window.closeUserDropdown = closeUserDropdown;

/**
 * Handle logout
 */
async function handleLogout() {
    if (typeof closeUserDropdown === 'function') closeUserDropdown();

    try {
        await AuthAPI.logout();
        showToast(txt('تم تسجيل الخروج بنجاح', 'Logged out successfully'), 'success');
    } catch (error) {
        // Even if API fails, clear local state
        AuthState.clearAuth();
    }

    // Reload to refresh UI
    window.location.reload();
}
window.handleLogout = handleLogout;

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const userMenu = document.getElementById('user-menu');
    if (userMenu && !userMenu.contains(e.target)) {
        closeUserDropdown();
    }
});

// Close dropdown on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeUserDropdown();
    }
});


// CSS for loading and error states
const apiClientStyles = document.createElement('style');
apiClientStyles.textContent = `
    .api-loading {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 60px 20px;
        color: var(--text-secondary, #888);
    }
    
    .api-loading .spinner {
        width: 40px;
        height: 40px;
        border: 3px solid rgba(0, 255, 136, 0.2);
        border-top-color: #00ff88;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin-bottom: 15px;
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    
    .api-error {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 60px 20px;
        color: #ff4444;
        text-align: center;
    }
    
    .api-error i {
        font-size: 3rem;
        margin-bottom: 15px;
    }
    
    .api-error p {
        margin-bottom: 20px;
        max-width: 400px;
    }
`;
document.head.appendChild(apiClientStyles);

console.log('✓ API Client loaded');

