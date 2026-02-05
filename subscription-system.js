/* ============================================================
   BREACHLABS - PREMIUM SUBSCRIPTION SYSTEM
   Professional subscription management with tiers and features
   ============================================================ */

const SubscriptionSystem = {
    // Subscription tiers
    tiers: {
        free: {
            name: 'Free',
            price: 0,
            priceMonthly: 0,
            features: [
                { text: 'Access to basic learning paths', included: true },
                { text: '5 practice rooms per month', included: true },
                { text: 'Community support', included: true },
                { text: 'Basic progress tracking', included: true },
                { text: 'Unlimited lab machines', included: false },
                { text: 'All CTF challenges', included: false },
                { text: 'Certificates', included: false },
                { text: 'Priority support', included: false }
            ],
            color: '#6b7280',
            icon: 'fa-user'
        },
        premium: {
            name: 'Premium',
            price: 99,
            priceMonthly: 9.99,
            features: [
                { text: 'Access to ALL learning paths', included: true },
                { text: 'Unlimited practice rooms', included: true },
                { text: 'Priority support', included: true },
                { text: 'Advanced analytics', included: true },
                { text: 'Unlimited lab machines', included: true },
                { text: 'All CTF challenges', included: true },
                { text: 'Verified certificates', included: true },
                { text: 'Exclusive content', included: true }
            ],
            color: '#22c55e',
            icon: 'fa-crown',
            popular: true
        },
        enterprise: {
            name: 'Enterprise',
            price: 'Custom',
            priceMonthly: 'Contact',
            features: [
                { text: 'Everything in Premium', included: true },
                { text: 'Custom learning paths', included: true },
                { text: 'Team management', included: true },
                { text: 'Dedicated support', included: true },
                { text: 'API access', included: true },
                { text: 'Custom integrations', included: true },
                { text: 'SLA guarantee', included: true },
                { text: 'On-premise option', included: true }
            ],
            color: '#a855f7',
            icon: 'fa-building'
        }
    },

    // Get current user subscription
    getCurrentSubscription() {
        const saved = localStorage.getItem('breachlabs_subscription');
        if (saved) {
            return JSON.parse(saved);
        }
        return {
            tier: 'free',
            status: 'active',
            startDate: new Date().toISOString(),
            endDate: null
        };
    },

    // Check if user is premium
    isPremium() {
        const sub = this.getCurrentSubscription();
        return sub.tier === 'premium' || sub.tier === 'enterprise';
    },

    // Upgrade subscription (mock)
    async upgrade(tier) {
        // Show loading
        if (window.LoadingPage) {
            LoadingPage.show('Processing subscription...');
        }

        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Save subscription
        const subscription = {
            tier: tier,
            status: 'active',
            startDate: new Date().toISOString(),
            endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString() // 1 year
        };

        localStorage.setItem('breachlabs_subscription', JSON.stringify(subscription));

        if (window.LoadingPage) {
            LoadingPage.hide();
        }

        // Show success toast
        this.showToast('🎉 Welcome to Premium! Enjoy unlimited access.', 'success');

        // Refresh navbar to show premium badge
        if (typeof MegaNavbar !== 'undefined' && MegaNavbar.render) {
            MegaNavbar.render();
        }

        return subscription;
    },

    // Show premium modal
    showPremiumModal() {
        // Remove existing modal
        const existing = document.getElementById('premium-modal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'premium-modal';
        modal.innerHTML = `
      <style>
        #premium-modal {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.9);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 99998;
          animation: modalFadeIn 0.3s ease;
          padding: 20px;
          overflow-y: auto;
        }
        
        @keyframes modalFadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        
        .premium-modal-content {
          background: linear-gradient(135deg, #1a1a2e 0%, #0f0f1a 100%);
          border-radius: 24px;
          max-width: 1000px;
          width: 100%;
          padding: 40px;
          position: relative;
          border: 1px solid rgba(34, 197, 94, 0.2);
          box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
        }
        
        .premium-close-btn {
          position: absolute;
          top: 20px;
          right: 20px;
          width: 40px;
          height: 40px;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.1);
          border: none;
          color: #fff;
          font-size: 20px;
          cursor: pointer;
          transition: all 0.3s;
        }
        
        .premium-close-btn:hover {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
        }
        
        .premium-header {
          text-align: center;
          margin-bottom: 40px;
        }
        
        .premium-header h2 {
          font-size: 2.5rem;
          font-weight: 800;
          color: #fff;
          margin-bottom: 10px;
        }
        
        .premium-header h2 span {
          color: #22c55e;
        }
        
        .premium-header p {
          color: rgba(255, 255, 255, 0.6);
          font-size: 16px;
        }
        
        .pricing-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 24px;
        }
        
        .pricing-card {
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 16px;
          padding: 30px;
          position: relative;
          transition: all 0.3s;
        }
        
        .pricing-card:hover {
          transform: translateY(-5px);
          border-color: var(--card-color, rgba(255, 255, 255, 0.2));
        }
        
        .pricing-card.popular {
          border-color: #22c55e;
          background: rgba(34, 197, 94, 0.05);
        }
        
        .popular-badge {
          position: absolute;
          top: -12px;
          left: 50%;
          transform: translateX(-50%);
          background: linear-gradient(135deg, #22c55e, #16a34a);
          color: #fff;
          padding: 6px 20px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        .pricing-icon {
          width: 50px;
          height: 50px;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 24px;
          margin-bottom: 20px;
        }
        
        .pricing-name {
          font-size: 24px;
          font-weight: 700;
          color: #fff;
          margin-bottom: 5px;
        }
        
        .pricing-price {
          margin-bottom: 25px;
        }
        
        .pricing-amount {
          font-size: 36px;
          font-weight: 800;
          color: #fff;
        }
        
        .pricing-period {
          color: rgba(255, 255, 255, 0.5);
          font-size: 14px;
        }
        
        .pricing-features {
          list-style: none;
          padding: 0;
          margin: 0 0 25px 0;
        }
        
        .pricing-features li {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 10px 0;
          color: rgba(255, 255, 255, 0.8);
          font-size: 14px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .pricing-features li:last-child {
          border-bottom: none;
        }
        
        .pricing-features li i {
          font-size: 14px;
        }
        
        .pricing-features li i.fa-check {
          color: #22c55e;
        }
        
        .pricing-features li i.fa-xmark {
          color: #ef4444;
          opacity: 0.5;
        }
        
        .pricing-features li.disabled {
          color: rgba(255, 255, 255, 0.3);
        }
        
        .pricing-btn {
          width: 100%;
          padding: 14px 20px;
          border-radius: 10px;
          font-size: 16px;
          font-weight: 700;
          cursor: pointer;
          transition: all 0.3s;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        .pricing-btn.primary {
          background: linear-gradient(135deg, #22c55e, #16a34a);
          color: #fff;
          border: none;
        }
        
        .pricing-btn.primary:hover {
          transform: scale(1.02);
          box-shadow: 0 10px 30px rgba(34, 197, 94, 0.4);
        }
        
        .pricing-btn.secondary {
          background: transparent;
          color: #fff;
          border: 2px solid rgba(255, 255, 255, 0.2);
        }
        
        .pricing-btn.secondary:hover {
          border-color: rgba(255, 255, 255, 0.4);
          background: rgba(255, 255, 255, 0.05);
        }
      </style>
      
      <div class="premium-modal-content">
        <button class="premium-close-btn" onclick="document.getElementById('premium-modal').remove()">
          <i class="fas fa-times"></i>
        </button>
        
        <div class="premium-header">
          <h2>Upgrade to <span>Premium</span></h2>
          <p>Unlock unlimited access to all features and content</p>
        </div>
        
        <div class="pricing-grid">
          ${Object.entries(this.tiers).map(([key, tier]) => `
            <div class="pricing-card ${tier.popular ? 'popular' : ''}" style="--card-color: ${tier.color}">
              ${tier.popular ? '<div class="popular-badge">Most Popular</div>' : ''}
              
              <div class="pricing-icon" style="background: ${tier.color}20; color: ${tier.color}">
                <i class="fas ${tier.icon}"></i>
              </div>
              
              <div class="pricing-name">${tier.name}</div>
              
              <div class="pricing-price">
                <span class="pricing-amount">
                  ${typeof tier.priceMonthly === 'number' ? '$' + tier.priceMonthly : tier.priceMonthly}
                </span>
                ${typeof tier.priceMonthly === 'number' ? '<span class="pricing-period">/month</span>' : ''}
              </div>
              
              <ul class="pricing-features">
                ${tier.features.map(f => `
                  <li class="${!f.included ? 'disabled' : ''}">
                    <i class="fas ${f.included ? 'fa-check' : 'fa-xmark'}"></i>
                    ${f.text}
                  </li>
                `).join('')}
              </ul>
              
              <button class="pricing-btn ${key === 'premium' ? 'primary' : 'secondary'}"
                onclick="SubscriptionSystem.handleUpgrade('${key}')">
                ${key === 'free' ? 'Current Plan' : key === 'enterprise' ? 'Contact Sales' : 'Upgrade Now'}
              </button>
            </div>
          `).join('')}
        </div>
      </div>
    `;

        document.body.appendChild(modal);

        // Close on backdrop click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    },

    // Handle upgrade click
    async handleUpgrade(tier) {
        if (tier === 'free') {
            this.showToast('You are already on the Free plan', 'info');
            return;
        }

        if (tier === 'enterprise') {
            this.showToast('Please contact sales@breachlabs.com for Enterprise plans', 'info');
            return;
        }

        // Close modal
        const modal = document.getElementById('premium-modal');
        if (modal) modal.remove();

        // Process upgrade
        await this.upgrade(tier);
    },

    // Show toast notification
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = 'subscription-toast';
        toast.innerHTML = `
      <style>
        .subscription-toast {
          position: fixed;
          bottom: 30px;
          right: 30px;
          padding: 16px 24px;
          background: ${type === 'success' ? '#22c55e' : type === 'error' ? '#ef4444' : '#667eea'};
          color: #fff;
          border-radius: 12px;
          font-weight: 600;
          z-index: 99999;
          animation: toastSlideIn 0.3s ease, toastSlideOut 0.3s ease 2.7s;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        @keyframes toastSlideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes toastSlideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
      </style>
      ${message}
    `;

        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    },

    // Get premium badge HTML
    getPremiumBadge() {
        if (!this.isPremium()) return '';
        return `
      <span style="
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 4px 10px;
        background: linear-gradient(135deg, #22c55e, #16a34a);
        color: #fff;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
      ">
        <i class="fas fa-crown"></i> PRO
      </span>
    `;
    }
};

// Export for global use
window.SubscriptionSystem = SubscriptionSystem;

// Hook into GO PREMIUM button
document.addEventListener('DOMContentLoaded', () => {
    // Override the premium button click
    document.addEventListener('click', (e) => {
        if (e.target.closest('.hud-premium') || e.target.closest('[onclick*="subscribe"]')) {
            e.preventDefault();
            e.stopPropagation();
            SubscriptionSystem.showPremiumModal();
        }
    });
});
