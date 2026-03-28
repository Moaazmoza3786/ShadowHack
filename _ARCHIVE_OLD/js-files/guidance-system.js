// ==================== SMART GUIDANCE SYSTEM ====================
// Adaptive learning recommendations based on student performance

const GuidanceSystem = {
    // Track performance per topic
    trackPerformance: function (userId, topic, score, isFailure) {
        const key = `guidance_${userId}_${topic}`;
        const data = JSON.parse(localStorage.getItem(key) || '{"attempts": 0, "failures": 0, "scores": [], "lastScore": null}');

        data.attempts++;
        if (isFailure || score < 60) data.failures++;
        data.scores.push(score);
        data.lastScore = score;
        data.avgScore = data.scores.reduce((a, b) => a + b, 0) / data.scores.length;
        data.lastUpdated = new Date().toISOString();

        localStorage.setItem(key, JSON.stringify(data));

        // Check if guidance is needed
        return this.checkGuidanceNeeded(userId, topic);
    },

    // Check if student needs guidance
    checkGuidanceNeeded: function (userId, topic) {
        const key = `guidance_${userId}_${topic}`;
        const data = JSON.parse(localStorage.getItem(key) || '{"attempts": 0, "failures": 0}');

        // Trigger if failed twice or score below 60
        if (data.failures >= 2) {
            return {
                needed: true,
                trigger: 'quiz_fail_2',
                message: txt(
                    'نلاحظ أنك تواجه صعوبة في هذا المفهوم. إليك بعض الموارد الإضافية!',
                    'We noticed you\'re having difficulty with this concept. Here are some extra resources!'
                ),
                suggestions: this.getSuggestions(topic)
            };
        }

        if (data.lastScore && data.lastScore < 60) {
            return {
                needed: true,
                trigger: 'score_below_60',
                message: txt(
                    'درجتك أقل من المطلوب. دعنا نراجع المفهوم معاً!',
                    'Your score is below required. Let\'s review the concept together!'
                ),
                suggestions: this.getSuggestions(topic)
            };
        }

        return { needed: false };
    },

    // Get supplementary content suggestions
    getSuggestions: function (topic) {
        const suggestions = {
            'sql_injection': [
                { type: 'video', title: 'Understanding UNION Attacks', titleAr: 'فهم هجمات UNION', duration: '5 min', url: '#' },
                { type: 'article', title: 'SQL Injection Cheat Sheet', titleAr: 'ورقة غش SQL Injection', url: '#' },
                { type: 'exercise', title: 'Practice: Basic SQLi', titleAr: 'تمرين: SQLi أساسي', url: '#' }
            ],
            'xss': [
                { type: 'video', title: 'XSS Filter Bypass Techniques', titleAr: 'تقنيات تجاوز فلاتر XSS', duration: '7 min', url: '#' },
                { type: 'article', title: 'XSS Types Explained', titleAr: 'شرح أنواع XSS', url: '#' }
            ],
            'authentication': [
                { type: 'video', title: 'Common Auth Vulnerabilities', titleAr: 'ثغرات المصادقة الشائعة', duration: '6 min', url: '#' },
                { type: 'exercise', title: 'Practice: Auth Bypass', titleAr: 'تمرين: تجاوز المصادقة', url: '#' }
            ]
        };

        return suggestions[topic] || [
            { type: 'article', title: 'General Security Resources', titleAr: 'موارد أمنية عامة', url: '#' }
        ];
    },

    // Show guidance popup
    showGuidancePopup: function (guidance) {
        if (!guidance.needed) return;

        const popup = document.createElement('div');
        popup.className = 'guidance-popup';
        popup.innerHTML = `
      <style>
        .guidance-popup {
          position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          border: 2px solid #667eea; border-radius: 20px; padding: 30px;
          max-width: 500px; width: 90%; z-index: 10000;
          box-shadow: 0 20px 60px rgba(0,0,0,0.5);
          animation: popIn 0.3s ease;
        }
        @keyframes popIn { from { transform: translate(-50%, -50%) scale(0.8); opacity: 0; } }
        .guidance-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 9999; }
        .guidance-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
        .guidance-icon { font-size: 2.5rem; }
        .guidance-title { font-size: 1.3rem; font-weight: 700; color: #fff; }
        .guidance-message { color: rgba(255,255,255,0.8); line-height: 1.6; margin-bottom: 20px; }
        .guidance-suggestions { display: flex; flex-direction: column; gap: 10px; }
        .suggestion-item { display: flex; align-items: center; gap: 12px; background: rgba(255,255,255,0.05); padding: 12px 15px; border-radius: 10px; cursor: pointer; transition: all 0.3s; }
        .suggestion-item:hover { background: rgba(102,126,234,0.2); }
        .suggestion-icon { width: 35px; height: 35px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1rem; }
        .suggestion-icon.video { background: #ef444433; color: #ef4444; }
        .suggestion-icon.article { background: #3b82f633; color: #3b82f6; }
        .suggestion-icon.exercise { background: #22c55e33; color: #22c55e; }
        .suggestion-text { flex: 1; }
        .suggestion-title { font-weight: 600; color: #fff; font-size: 0.95rem; }
        .suggestion-meta { color: rgba(255,255,255,0.5); font-size: 0.8rem; }
        .guidance-close { position: absolute; top: 15px; right: 15px; background: none; border: none; color: rgba(255,255,255,0.5); font-size: 1.5rem; cursor: pointer; }
        .guidance-close:hover { color: #fff; }
        .guidance-later { background: rgba(255,255,255,0.1); border: none; padding: 10px 25px; border-radius: 8px; color: #fff; cursor: pointer; margin-top: 15px; width: 100%; }
        .guidance-later:hover { background: rgba(255,255,255,0.2); }
      </style>
      <div class="guidance-overlay" onclick="this.parentElement.remove()"></div>
      <button class="guidance-close" onclick="this.parentElement.remove()">×</button>
      <div class="guidance-header">
        <div class="guidance-icon">💡</div>
        <div class="guidance-title">${txt('مساعدة ذكية', 'Smart Assistance')}</div>
      </div>
      <div class="guidance-message">${guidance.message}</div>
      <div class="guidance-suggestions">
        ${guidance.suggestions.map(s => `
          <div class="suggestion-item" onclick="window.open('${s.url}', '_blank')">
            <div class="suggestion-icon ${s.type}">
              <i class="fas fa-${s.type === 'video' ? 'play' : s.type === 'article' ? 'file-alt' : 'flask'}"></i>
            </div>
            <div class="suggestion-text">
              <div class="suggestion-title">${currentLang === 'ar' ? s.titleAr : s.title}</div>
              <div class="suggestion-meta">${s.type === 'video' ? s.duration : s.type}</div>
            </div>
            <i class="fas fa-chevron-right" style="color: rgba(255,255,255,0.3)"></i>
          </div>
        `).join('')}
      </div>
      <button class="guidance-later" onclick="this.parentElement.remove()">
        ${txt('ذكرني لاحقاً', 'Remind Me Later')}
      </button>
    `;

        document.body.appendChild(popup);
    },

    // Reset performance for a topic
    resetPerformance: function (userId, topic) {
        const key = `guidance_${userId}_${topic}`;
        localStorage.removeItem(key);
    },

    // Get all performance data for user
    getAllPerformance: function (userId) {
        const data = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(`guidance_${userId}_`)) {
                const topic = key.replace(`guidance_${userId}_`, '');
                data[topic] = JSON.parse(localStorage.getItem(key));
            }
        }
        return data;
    }
};

// Export for global use
window.GuidanceSystem = GuidanceSystem;

// Integration with quiz completion
window.onQuizComplete = function (userId, topic, score) {
    const guidance = GuidanceSystem.trackPerformance(userId, topic, score, score < 60);
    if (guidance.needed) {
        setTimeout(() => GuidanceSystem.showGuidancePopup(guidance), 500);
    }
};
