"""
Email Service for ShadowHack
Handles sending email notifications, digests, and alerts
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from models import db, User, Notification
import os
from dotenv import load_dotenv

load_dotenv()

class EmailService:
    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD')
        self.enabled = bool(self.sender_email and self.sender_password)

    def send_email(self, recipient_email, subject, html_content):
        """Send email with HTML content"""
        if not self.enabled:
            print("Email service not configured")
            return False

        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = recipient_email

            # Attach HTML content
            part = MIMEText(html_content, "html")
            message.attach(part)

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient_email, message.as_string())

            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False

    def send_achievement_notification(self, user_email, achievement_name, description):
        """Send achievement notification email"""
        html_content = f"""
        <html>
            <body style="font-family: 'Arial', sans-serif; background: #0a0e27; color: #fff;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: linear-gradient(135deg, #33abff, #ff0055); padding: 20px; border-radius: 10px; text-align: center;">
                        <h1 style="margin: 0;">🏆 Achievement Unlocked!</h1>
                    </div>
                    <div style="background: #1a1f3a; padding: 20px; margin-top: 20px; border-radius: 10px;">
                        <h2 style="color: #33abff;">{achievement_name}</h2>
                        <p>{description}</p>
                        <p style="color: #999; font-size: 12px; margin-top: 20px;">
                            Keep up the great work on your cybersecurity learning journey!
                        </p>
                    </div>
                </div>
            </body>
        </html>
        """
        return self.send_email(user_email, f"🏆 Achievement Unlocked: {achievement_name}", html_content)

    def send_daily_digest(self, user_email, user_name, notifications_data):
        """Send daily notification digest"""
        notifications_html = ""
        for notif in notifications_data[:10]:  # Limit to 10
            notifications_html += f"""
            <div style="background: #0a0e27; padding: 15px; margin: 10px 0; border-left: 3px solid #33abff; border-radius: 5px;">
                <h4 style="margin: 0 0 5px 0; color: #33abff;">{notif.get('title', 'Notification')}</h4>
                <p style="margin: 0; color: #ccc; font-size: 14px;">{notif.get('message', '')}</p>
                <p style="margin: 10px 0 0 0; color: #999; font-size: 12px;">{notif.get('created_at', '')}</p>
            </div>
            """

        html_content = f"""
        <html>
            <body style="font-family: 'Arial', sans-serif; background: #0a0e27; color: #fff;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: linear-gradient(135deg, #33abff, #00d4ff); padding: 20px; border-radius: 10px; text-align: center;">
                        <h1 style="margin: 0;">📬 Your Daily Digest</h1>
                        <p style="margin: 5px 0 0 0; color: #1a1f3a;">{datetime.now().strftime('%A, %B %d, %Y')}</p>
                    </div>
                    <div style="background: #1a1f3a; padding: 20px; margin-top: 20px; border-radius: 10px;">
                        <h2 style="color: #33abff; margin-top: 0;">Hello {user_name}! 👋</h2>
                        <p>Here's what's been happening in your ShadowHack account:</p>
                        {notifications_html}
                        <a href="https://shadowhack.com/notifications" style="display: inline-block; margin-top: 20px; padding: 12px 24px; background: #33abff; color: #1a1f3a; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            View All Notifications
                        </a>
                    </div>
                    <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
                        <p>You can manage your email preferences in your account settings</p>
                    </div>
                </div>
            </body>
        </html>
        """
        return self.send_email(user_email, "📬 Your Daily Digest - ShadowHack", html_content)

    def send_challenge_notification(self, user_email, challenge_name, difficulty, xp_reward):
        """Send new challenge notification"""
        html_content = f"""
        <html>
            <body style="font-family: 'Arial', sans-serif; background: #0a0e27; color: #fff;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: linear-gradient(135deg, #ff6b00, #ff0055); padding: 20px; border-radius: 10px; text-align: center;">
                        <h1 style="margin: 0;">🎯 New Challenge Available!</h1>
                    </div>
                    <div style="background: #1a1f3a; padding: 20px; margin-top: 20px; border-radius: 10px;">
                        <h2 style="color: #ff6b00;">{challenge_name}</h2>
                        <p style="font-size: 16px; margin: 10px 0;">
                            <span style="background: #ff6b00; color: #fff; padding: 5px 10px; border-radius: 5px; font-weight: bold;">
                                {difficulty}
                            </span>
                            <span style="color: #4ade80; font-weight: bold; margin-left: 10px;">+{xp_reward} XP</span>
                        </p>
                        <a href="https://shadowhack.com/challenges/{challenge_name}" style="display: inline-block; margin-top: 20px; padding: 12px 24px; background: #ff6b00; color: #fff; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            Start Challenge
                        </a>
                    </div>
                </div>
            </body>
        </html>
        """
        return self.send_email(user_email, f"🎯 New Challenge: {challenge_name}", html_content)

    def send_streak_milestone(self, user_email, user_name, streak_days):
        """Send streak milestone notification"""
        html_content = f"""
        <html>
            <body style="font-family: 'Arial', sans-serif; background: #0a0e27; color: #fff;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: linear-gradient(135deg, #ff0000, #ff6b00); padding: 20px; border-radius: 10px; text-align: center;">
                        <h1 style="margin: 0;">🔥 Streak Milestone!</h1>
                    </div>
                    <div style="background: #1a1f3a; padding: 20px; margin-top: 20px; border-radius: 10px;">
                        <h2 style="color: #ff6b00;">You're on Fire! 🔥</h2>
                        <p style="font-size: 18px; margin: 10px 0;">
                            <span style="font-weight: bold; color: #4ade80;">{streak_days} Day Streak!</span>
                        </p>
                        <p>Amazing dedication! Keep this momentum going and unlock more achievements. You're making great progress on your cybersecurity journey!</p>
                        <a href="https://shadowhack.com/dashboard" style="display: inline-block; margin-top: 20px; padding: 12px 24px; background: #ff6b00; color: #fff; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            View Progress
                        </a>
                    </div>
                </div>
            </body>
        </html>
        """
        return self.send_email(user_email, f"🔥 {streak_days}-Day Streak Milestone!", html_content)


# Create singleton instance
email_service = EmailService()


def send_daily_digests():
    """Scheduled task to send daily digests to all users"""
    users = User.query.filter_by(email_digest_enabled=True).all()
    
    for user in users:
        # Get notifications from last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        notifications = Notification.query.filter(
            Notification.user_id == user.id,
            Notification.created_at >= yesterday
        ).order_by(Notification.created_at.desc()).all()

        if notifications:
            notif_data = [n.to_dict() for n in notifications]
            email_service.send_daily_digest(
                user.email,
                user.username,
                notif_data
            )

if __name__ == "__main__":
    # Test email sending
    service = EmailService()
    test_email = "test@example.com"
    
    service.send_achievement_notification(
        test_email,
        "Web Security Mastery",
        "You've completed all web security labs!"
    )
