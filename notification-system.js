/* ============================================================
   NOTIFICATION SYSTEM - BreachLabs
   Global toast notification system for user feedback
   ============================================================ */

const NotificationSystem = {
    container: null,

    init() {
        // Create toast container if it doesn't exist
        if (!document.getElementById('toast-container')) {
            const container = document.createElement('div');
            container.id = 'toast-container';
            container.style.cssText = `
                position: fixed;
                top: 80px;
                right: 20px;
                z-index: 99999;
                display: flex;
                flex-direction: column;
                gap: 10px;
                max-width: 400px;
            `;
            document.body.appendChild(container);
            this.container = container;
        } else {
            this.container = document.getElementById('toast-container');
        }
    },

    show(message, type = 'info', duration = 4000) {
        if (!this.container) this.init();

        const toast = document.createElement('div');
        toast.className = `toast-notification toast-${type}`;

        // Icon based on type
        const icons = {
            success: 'fa-circle-check',
            error: 'fa-circle-xmark',
            warning: 'fa-triangle-exclamation',
            info: 'fa-circle-info',
            danger: 'fa-circle-xmark'
        };

        // Colors based on type
        const colors = {
            success: { bg: '#10b981', border: '#059669' },
            error: { bg: '#ef4444', border: '#dc2626' },
            danger: { bg: '#ef4444', border: '#dc2626' },
            warning: { bg: '#f59e0b', border: '#d97706' },
            info: { bg: '#3b82f6', border: '#2563eb' }
        };

        const color = colors[type] || colors.info;
        const icon = icons[type] || icons.info;

        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 12px;">
                <i class="fa-solid ${icon}" style="font-size: 20px;"></i>
                <span style="flex: 1;">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" 
                        style="background: none; border: none; color: inherit; cursor: pointer; padding: 4px; opacity: 0.7;">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <div class="toast-progress" style="
                position: absolute;
                bottom: 0;
                left: 0;
                height: 3px;
                background: rgba(255,255,255,0.5);
                animation: toast-progress ${duration}ms linear forwards;
            "></div>
        `;

        toast.style.cssText = `
            background: ${color.bg};
            color: white;
            padding: 14px 18px;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            border-left: 4px solid ${color.border};
            position: relative;
            overflow: hidden;
            animation: toast-slide-in 0.3s ease-out;
            font-size: 14px;
            font-weight: 500;
        `;

        this.container.appendChild(toast);

        // Auto-remove after duration
        setTimeout(() => {
            toast.style.animation = 'toast-slide-out 0.3s ease-in forwards';
            setTimeout(() => toast.remove(), 300);
        }, duration);

        return toast;
    },

    success(message, duration) {
        return this.show(message, 'success', duration);
    },

    error(message, duration) {
        return this.show(message, 'error', duration);
    },

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    },

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
};

// Inject CSS for animations
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    @keyframes toast-slide-in {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes toast-slide-out {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    @keyframes toast-progress {
        from { width: 100%; }
        to { width: 0%; }
    }
`;
document.head.appendChild(toastStyles);

// Global function for backward compatibility
function showToast(message, type = 'info', duration = 4000) {
    return NotificationSystem.show(message, type, duration);
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    NotificationSystem.init();
});

// Auto-init if DOM already loaded
if (document.readyState !== 'loading') {
    NotificationSystem.init();
}

// Export
window.NotificationSystem = NotificationSystem;
window.showToast = showToast;
