/* ==================== UI ENHANCEMENTS ==================== */
/* A: Skeleton Loaders, C: Mobile Responsive, D: Performance, F: Micro-animations */

// ============== A. SKELETON LOADERS ==============
function showSkeletonLoader(container, type = 'cards', count = 6) {
    if (!container) return;

    const skeletons = {
        cards: `
            <div class="skeleton-card">
                <div class="skeleton-image skeleton-pulse"></div>
                <div class="skeleton-content">
                    <div class="skeleton-title skeleton-pulse"></div>
                    <div class="skeleton-text skeleton-pulse"></div>
                    <div class="skeleton-text short skeleton-pulse"></div>
                </div>
            </div>
        `,
        list: `
            <div class="skeleton-list-item">
                <div class="skeleton-avatar skeleton-pulse"></div>
                <div class="skeleton-list-content">
                    <div class="skeleton-title skeleton-pulse"></div>
                    <div class="skeleton-text skeleton-pulse"></div>
                </div>
            </div>
        `,
        video: `
            <div class="skeleton-video">
                <div class="skeleton-video-player skeleton-pulse"></div>
                <div class="skeleton-video-info">
                    <div class="skeleton-title skeleton-pulse"></div>
                    <div class="skeleton-text skeleton-pulse"></div>
                </div>
            </div>
        `
    };

    let html = '<div class="skeleton-container">';
    for (let i = 0; i < count; i++) {
        html += skeletons[type] || skeletons.cards;
    }
    html += '</div>';

    container.innerHTML = html;
}

// ============== D. LAZY LOADING ==============
function initLazyLoading() {
    // Intersection Observer for lazy loading images
    if ('IntersectionObserver' in window) {
        const lazyImages = document.querySelectorAll('img[data-src]');

        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.add('loaded');
                    observer.unobserve(img);
                }
            });
        }, { rootMargin: '50px 0px' });

        lazyImages.forEach(img => imageObserver.observe(img));
    }
}

// Debounce function for performance
function debounce(func, wait = 100) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Throttle function for scroll events
function throttle(func, limit = 100) {
    let inThrottle;
    return function (...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ============== F. MICRO-ANIMATIONS ==============
function initMicroAnimations() {
    // Add staggered animation to elements
    document.querySelectorAll('.animate-stagger').forEach((container, i) => {
        container.querySelectorAll('.animate-item').forEach((item, index) => {
            item.style.animationDelay = `${index * 0.1}s`;
        });
    });
}

// Smooth scroll to element
function smoothScrollTo(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ============== INJECT STYLES ==============
function injectEnhancementStyles() {
    if (document.getElementById('ui-enhancements-styles')) return;

    const styles = document.createElement('style');
    styles.id = 'ui-enhancements-styles';
    styles.textContent = `
        /* ========== A. SKELETON LOADERS ========== */
        .skeleton-container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
            padding: 20px;
        }
        
        .skeleton-card {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.05);
        }
        
        .skeleton-image {
            height: 160px;
            background: rgba(255,255,255,0.05);
        }
        
        .skeleton-content {
            padding: 20px;
        }
        
        .skeleton-title {
            height: 20px;
            background: rgba(255,255,255,0.08);
            border-radius: 4px;
            margin-bottom: 12px;
            width: 70%;
        }
        
        .skeleton-text {
            height: 14px;
            background: rgba(255,255,255,0.05);
            border-radius: 4px;
            margin-bottom: 8px;
        }
        
        .skeleton-text.short {
            width: 50%;
        }
        
        .skeleton-pulse {
            animation: skeletonPulse 1.5s ease-in-out infinite;
        }
        
        @keyframes skeletonPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }
        
        .skeleton-list-item {
            display: flex;
            gap: 15px;
            padding: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        
        .skeleton-avatar {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: rgba(255,255,255,0.08);
            flex-shrink: 0;
        }
        
        .skeleton-list-content {
            flex: 1;
        }
        
        .skeleton-video-player {
            width: 100%;
            aspect-ratio: 16/9;
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
        }
        
        .skeleton-video-info {
            padding: 15px 0;
        }
        
        /* ========== C. MOBILE RESPONSIVE ========== */
        @media (max-width: 768px) {
            /* Navigation */
            .mega-nav { padding: 10px 15px !important; }
            .mega-nav-brand { font-size: 1.2rem !important; }
            
            /* Cards Grid */
            .skeleton-container,
            .yt-grid,
            .ctf-grid,
            .features-grid,
            .ach-grid,
            .notes-grid,
            .qlinks-grid {
                grid-template-columns: 1fr !important;
                gap: 15px !important;
                padding: 15px !important;
            }
            
            /* Hero Section */
            .hero-title { font-size: 2rem !important; }
            .hero-subtitle { font-size: 1.2rem !important; }
            .hero-desc { font-size: 1rem !important; }
            .hero-actions { flex-direction: column !important; gap: 10px !important; }
            .cyber-btn { width: 100% !important; }
            
            /* Leaderboard */
            .lb-podium { flex-direction: column !important; gap: 15px !important; }
            .podium-item { order: 0 !important; }
            .podium-1 { order: -1 !important; }
            
            /* Daily Section */
            .daily-wrapper { grid-template-columns: 1fr !important; }
            
            /* CTF Challenge */
            .ctf-challenge-page .row { flex-direction: column !important; }
            .ctf-challenge-page .col-lg-8,
            .ctf-challenge-page .col-lg-4 { width: 100% !important; max-width: 100% !important; }
            
            /* YouTube Player */
            .yt-watch-page .row { flex-direction: column !important; }
            .yt-watch-page .col-lg-8,
            .yt-watch-page .col-lg-4 { width: 100% !important; max-width: 100% !important; }
            .yt-playlist-panel { max-height: 300px !important; }
            
            /* Section Headers */
            .section-title { font-size: 1.8rem !important; }
            .lb-header h1,
            .ach-header h1,
            .notes-title { font-size: 1.5rem !important; }
            
            /* Stats */
            .ach-stats { flex-direction: column !important; gap: 20px !important; }
            .hero-stats { flex-direction: column !important; gap: 15px !important; }
            .stat-divider { display: none !important; }
            
            /* Buttons */
            .filter-btn { padding: 8px 12px !important; font-size: 0.8rem !important; }
            
            /* Modal */
            .note-modal-content { width: 95% !important; padding: 20px !important; }
        }
        
        @media (max-width: 480px) {
            .hero-title { font-size: 1.6rem !important; }
            .hero-visual { display: none !important; }
            .podium-avatar { width: 60px !important; height: 60px !important; font-size: 1.8rem !important; }
            .podium-stand { padding: 15px 20px !important; }
        }
        
        /* ========== F. MICRO-ANIMATIONS ========== */
        /* Hover Effects */
        .hover-lift {
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .hover-lift:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }
        
        .hover-glow {
            transition: box-shadow 0.3s ease;
        }
        .hover-glow:hover {
            box-shadow: 0 0 30px rgba(0,255,136,0.3);
        }
        
        .hover-scale {
            transition: transform 0.2s ease;
        }
        .hover-scale:hover {
            transform: scale(1.05);
        }
        
        /* Button Animations */
        .btn-animate {
            position: relative;
            overflow: hidden;
        }
        .btn-animate::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(255,255,255,0.2);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            transition: width 0.4s ease, height 0.4s ease;
        }
        .btn-animate:hover::after {
            width: 300px;
            height: 300px;
        }
        
        /* Card Animations */
        .card-animate {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .card-animate:hover {
            transform: translateY(-10px) scale(1.02);
            box-shadow: 0 25px 50px rgba(0,0,0,0.4);
        }
        
        /* Staggered Animations */
        .animate-stagger .animate-item {
            opacity: 0;
            transform: translateY(20px);
            animation: fadeInUp 0.5s ease forwards;
        }
        
        @keyframes fadeInUp {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Icon Spin on Hover */
        .icon-spin:hover i {
            animation: iconSpin 0.5s ease;
        }
        @keyframes iconSpin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        /* Pulse Animation */
        .pulse-animate {
            animation: pulseGlow 2s ease infinite;
        }
        @keyframes pulseGlow {
            0%, 100% { box-shadow: 0 0 0 0 rgba(0,255,136,0.4); }
            50% { box-shadow: 0 0 0 15px rgba(0,255,136,0); }
        }
        
        /* Text Gradient Animation */
        .text-gradient-animate {
            background: linear-gradient(90deg, #00ff88, #00ccff, #ff0055, #00ff88);
            background-size: 300% 100%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientFlow 3s ease infinite;
        }
        @keyframes gradientFlow {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        /* Lazy Load Fade */
        img[data-src] {
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        img.loaded {
            opacity: 1;
        }
        
        /* Smooth Page Transitions */
        .page-transition {
            animation: pageSlideIn 0.3s ease-out;
        }
        @keyframes pageSlideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
    `;

    document.head.appendChild(styles);
}

// ============== INIT ON LOAD ==============
document.addEventListener('DOMContentLoaded', () => {
    injectEnhancementStyles();
    initLazyLoading();
    initMicroAnimations();

    // Re-init on page change
    window.addEventListener('hashchange', () => {
        setTimeout(() => {
            initLazyLoading();
            initMicroAnimations();
        }, 100);
    });
});

// ============== EXPORTS ==============
window.showSkeletonLoader = showSkeletonLoader;
window.initLazyLoading = initLazyLoading;
window.debounce = debounce;
window.throttle = throttle;
window.smoothScrollTo = smoothScrollTo;
