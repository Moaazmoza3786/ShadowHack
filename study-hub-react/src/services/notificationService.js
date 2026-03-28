/**
 * Notification Service
 * Handles desktop push notifications, email digests, and event-based triggers
 */

class NotificationService {
    constructor() {
        this.notifications = [];
        this.subscribed = false;
        this.emailPreferences = {
            dailyDigest: true,
            achievements: true,
            challenges: true,
            newCourses: false,
        };
        this.initBrowserNotifications();
    }

    /**
     * Request browser notification permission
     */
    async initBrowserNotifications() {
        if ('Notification' in window && Notification.permission === 'default') {
            try {
                const permission = await Notification.requestPermission();
                this.subscribed = permission === 'granted';
            } catch (error) {
                console.error('Notification permission error:', error);
            }
        } else if ('Notification' in window) {
            this.subscribed = Notification.permission === 'granted';
        }
    }

    /**
     * Send browser push notification
     */
    sendBrowserNotification(title, options = {}) {
        if (!this.subscribed || !('Notification' in window)) return;

        const defaultOptions = {
            icon: '/shadowhack-icon.png',
            badge: '/shadowhack-badge.png',
            tag: 'shadowhack-notification',
            requireInteraction: false,
            ...options,
        };

        new Notification(title, defaultOptions);
    }

    /**
     * Send achievement notification
     */
    notifyAchievement(achievement) {
        const notification = {
            id: Date.now(),
            type: 'achievement',
            title: `🏆 Achievement Unlocked: ${achievement.name}`,
            description: achievement.description,
            icon: '🏆',
            timestamp: new Date(),
            read: false,
            data: achievement,
        };

        this.notifications.unshift(notification);
        this.sendBrowserNotification(notification.title, {
            body: achievement.description,
            tag: `achievement-${achievement.id}`,
        });

        // Trigger email if enabled
        if (this.emailPreferences.achievements) {
            this.scheduleEmail('achievement', achievement);
        }

        return notification;
    }

    /**
     * Send lab completion notification
     */
    notifyLabCompleted(lab) {
        const notification = {
            id: Date.now(),
            type: 'lab_completed',
            title: `✅ Lab Completed: ${lab.name}`,
            description: `You've earned +${lab.xpReward} XP`,
            icon: '✅',
            timestamp: new Date(),
            read: false,
            data: lab,
        };

        this.notifications.unshift(notification);
        this.sendBrowserNotification(notification.title, {
            body: `${lab.difficulty} - +${lab.xpReward} XP`,
            tag: `lab-${lab.id}`,
        });

        return notification;
    }

    /**
     * Send challenge notification
     */
    notifyNewChallenge(challenge) {
        if (!this.emailPreferences.challenges) return;

        const notification = {
            id: Date.now(),
            type: 'new_challenge',
            title: `🎯 New Challenge: ${challenge.name}`,
            description: `${challenge.difficulty} - ${challenge.reward} XP`,
            icon: '🎯',
            timestamp: new Date(),
            read: false,
            data: challenge,
        };

        this.notifications.unshift(notification);
        this.sendBrowserNotification(notification.title, {
            body: challenge.description,
            tag: `challenge-${challenge.id}`,
        });

        this.scheduleEmail('challenge', challenge);
        return notification;
    }

    /**
     * Send course update notification
     */
    notifyNewCourse(course) {
        if (!this.emailPreferences.newCourses) return;

        const notification = {
            id: Date.now(),
            type: 'new_course',
            title: `📚 New Course: ${course.name}`,
            description: course.description,
            icon: '📚',
            timestamp: new Date(),
            read: false,
            data: course,
        };

        this.notifications.unshift(notification);
        this.sendBrowserNotification(notification.title, {
            body: course.description,
            tag: `course-${course.id}`,
        });

        return notification;
    }

    /**
     * Send streak notification
     */
    notifyStreakMilestone(streak) {
        const notification = {
            id: Date.now(),
            type: 'streak',
            title: `🔥 Streak Milestone: ${streak} days!`,
            description: `Keep up the momentum! You're on fire!`,
            icon: '🔥',
            timestamp: new Date(),
            read: false,
            data: { streak },
        };

        this.notifications.unshift(notification);
        this.sendBrowserNotification(notification.title, {
            body: `You've maintained a ${streak}-day streak!`,
            tag: `streak-${streak}`,
        });

        return notification;
    }

    /**
     * Send general notification
     */
    notify(type, title, description, data = {}) {
        const notification = {
            id: Date.now(),
            type,
            title,
            description,
            icon: '📬',
            timestamp: new Date(),
            read: false,
            data,
        };

        this.notifications.unshift(notification);
        this.sendBrowserNotification(title, {
            body: description,
            tag: `${type}-${notification.id}`,
        });

        return notification;
    }

    /**
     * Get all notifications
     */
    getNotifications(unreadOnly = false) {
        if (unreadOnly) {
            return this.notifications.filter(n => !n.read);
        }
        return this.notifications;
    }

    /**
     * Mark notification as read
     */
    markAsRead(notificationId) {
        const notification = this.notifications.find(n => n.id === notificationId);
        if (notification) {
            notification.read = true;
        }
    }

    /**
     * Clear all notifications
     */
    clearAll() {
        this.notifications = [];
    }

    /**
     * Schedule email notification
     */
    scheduleEmail(type, data) {
        // In a real app, this would send to backend
        console.log(`Scheduled ${type} email:`, data);
    }

    /**
     * Send email digest (daily, weekly, etc.)
     */
    async sendEmailDigest() {
        if (!this.emailPreferences.dailyDigest) return;

        const payload = {
            unreadCount: this.getNotifications(true).length,
            notifications: this.getNotifications().slice(0, 20),
            timestamp: new Date(),
        };

        // In a real app, POST to /api/email/digest
        console.log('Email digest sent:', payload);
    }

    /**
     * Update email preferences
     */
    updateEmailPreferences(preferences) {
        this.emailPreferences = { ...this.emailPreferences, ...preferences };
        localStorage.setItem('shadowhack-email-prefs', JSON.stringify(this.emailPreferences));
    }

    /**
     * Get email preferences
     */
    getEmailPreferences() {
        return this.emailPreferences;
    }
}

// Create singleton instance
const notificationService = new NotificationService();

export default notificationService;
