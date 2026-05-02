import React, { useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  Switch,
} from 'react-native';

const ProfileScreen = () => {
  const [profile, setProfile] = useState({
    username: 'HackerPro',
    email: 'hacker@example.com',
    bio: 'Cybersecurity enthusiast | Bug Hunter',
    level: 12,
    xp_points: 5420,
    certifications: 5,
  });

  const [notifications, setNotifications] = useState({
    push: true,
    email: true,
    achievements: true,
    leaderboard: false,
  });

  const toggleNotification = (key) => {
    setNotifications({ ...notifications, [key]: !notifications[key] });
  };

  const certifications = [
    { name: 'CEH', issuer: 'EC-Council', status: 'verified' },
    { name: 'OSCP', issuer: 'Offensive Security', status: 'verified' },
    { name: 'Security+', issuer: 'CompTIA', status: 'verified' },
    { name: 'GPEN', issuer: 'GIAC', status: 'pending' },
    { name: 'CISSP', issuer: 'ISC²', status: 'in_progress' },
  ];

  return (
    <ScrollView style={styles.container}>
      {/* Profile Header */}
      <View style={styles.profileHeader}>
        <View style={styles.avatar}>
          <Text style={styles.avatarEmoji}>🧑‍💻</Text>
        </View>
        <Text style={styles.username}>{profile.username}</Text>
        <Text style={styles.email}>{profile.email}</Text>
        <Text style={styles.bio}>{profile.bio}</Text>
      </View>

      {/* Stats */}
      <View style={styles.statsRow}>
        <View style={styles.statCard}>
          <Text style={styles.statLabel}>Level</Text>
          <Text style={styles.statValue}>{profile.level}</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statLabel}>XP Points</Text>
          <Text style={styles.statValue}>{profile.xp_points}</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={styles.statLabel}>Certs</Text>
          <Text style={styles.statValue}>{profile.certifications}</Text>
        </View>
      </View>

      {/* Certifications */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Certifications</Text>
        {certifications.map((cert, idx) => (
          <View key={idx} style={styles.certCard}>
            <View style={styles.certInfo}>
              <Text style={styles.certName}>{cert.name}</Text>
              <Text style={styles.certIssuer}>{cert.issuer}</Text>
            </View>
            <Text
              style={[
                styles.certStatus,
                cert.status === 'verified' && styles.certStatusVerified,
                cert.status === 'pending' && styles.certStatusPending,
                cert.status === 'in_progress' && styles.certStatusProgress,
              ]}
            >
              {cert.status === 'verified' && '✓'}
              {cert.status === 'pending' && '⏳'}
              {cert.status === 'in_progress' && '⚙️'}
            </Text>
          </View>
        ))}
      </View>

      {/* Notifications */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Notifications</Text>

        <View style={styles.settingRow}>
          <View>
            <Text style={styles.settingLabel}>Push Notifications</Text>
            <Text style={styles.settingDesc}>Receive mobile alerts</Text>
          </View>
          <Switch
            value={notifications.push}
            onValueChange={() => toggleNotification('push')}
            trackColor={{ false: '#3a3f5a', true: '#00ff8844' }}
            thumbColor={notifications.push ? '#00ff88' : '#666'}
          />
        </View>

        <View style={styles.settingRow}>
          <View>
            <Text style={styles.settingLabel}>Email Notifications</Text>
            <Text style={styles.settingDesc}>Daily digest emails</Text>
          </View>
          <Switch
            value={notifications.email}
            onValueChange={() => toggleNotification('email')}
            trackColor={{ false: '#3a3f5a', true: '#00ff8844' }}
            thumbColor={notifications.email ? '#00ff88' : '#666'}
          />
        </View>

        <View style={styles.settingRow}>
          <View>
            <Text style={styles.settingLabel}>Achievement Alerts</Text>
            <Text style={styles.settingDesc}>When you unlock badges</Text>
          </View>
          <Switch
            value={notifications.achievements}
            onValueChange={() => toggleNotification('achievements')}
            trackColor={{ false: '#3a3f5a', true: '#00ff8844' }}
            thumbColor={notifications.achievements ? '#00ff88' : '#666'}
          />
        </View>

        <View style={styles.settingRow}>
          <View>
            <Text style={styles.settingLabel}>Leaderboard Updates</Text>
            <Text style={styles.settingDesc}>Ranking changes</Text>
          </View>
          <Switch
            value={notifications.leaderboard}
            onValueChange={() => toggleNotification('leaderboard')}
            trackColor={{ false: '#3a3f5a', true: '#00ff8844' }}
            thumbColor={notifications.leaderboard ? '#00ff88' : '#666'}
          />
        </View>
      </View>

      {/* Account Settings */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Account</Text>

        <TouchableOpacity style={styles.menuButton}>
          <Text style={styles.menuButtonText}>🔐 Change Password</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.menuButton}>
          <Text style={styles.menuButtonText}>🔗 Connect Accounts</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.menuButton}>
          <Text style={styles.menuButtonText}>⚙️ Preferences</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.menuButton}>
          <Text style={styles.menuButtonText}>📚 Help & Support</Text>
        </TouchableOpacity>
      </View>

      {/* Logout */}
      <TouchableOpacity style={styles.logoutButton}>
        <Text style={styles.logoutButtonText}>Logout</Text>
      </TouchableOpacity>

      <View style={styles.spacer} />
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e27',
  },
  profileHeader: {
    alignItems: 'center',
    paddingVertical: 30,
    borderBottomColor: '#1a1f3a',
    borderBottomWidth: 1,
  },
  avatar: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#1a1f3a',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 12,
    borderColor: '#00ff88',
    borderWidth: 2,
  },
  avatarEmoji: {
    fontSize: 40,
  },
  username: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#fff',
  },
  email: {
    fontSize: 14,
    color: '#888',
    marginTop: 4,
  },
  bio: {
    fontSize: 13,
    color: '#aaa',
    marginTop: 8,
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingHorizontal: 16,
    paddingVertical: 20,
    gap: 8,
  },
  statCard: {
    flex: 1,
    padding: 12,
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    borderColor: '#2a2f4a',
    borderWidth: 1,
    alignItems: 'center',
  },
  statLabel: {
    fontSize: 12,
    color: '#888',
    marginBottom: 4,
  },
  statValue: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#00ff88',
  },
  section: {
    paddingHorizontal: 16,
    marginVertical: 20,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 12,
  },
  certCard: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    paddingHorizontal: 14,
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    marginBottom: 8,
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  certInfo: {
    flex: 1,
  },
  certName: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#fff',
  },
  certIssuer: {
    fontSize: 12,
    color: '#888',
    marginTop: 2,
  },
  certStatus: {
    fontSize: 16,
  },
  certStatusVerified: {
    color: '#00ff88',
  },
  certStatusPending: {
    color: '#ffaa00',
  },
  certStatusProgress: {
    color: '#00ccff',
  },
  settingRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    paddingHorizontal: 14,
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    marginBottom: 8,
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  settingLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#fff',
  },
  settingDesc: {
    fontSize: 12,
    color: '#888',
    marginTop: 2,
  },
  menuButton: {
    paddingVertical: 12,
    paddingHorizontal: 14,
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    marginBottom: 8,
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  menuButtonText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#fff',
  },
  logoutButton: {
    marginHorizontal: 16,
    marginVertical: 20,
    paddingVertical: 14,
    backgroundColor: '#ff3333',
    borderRadius: 10,
    alignItems: 'center',
  },
  logoutButtonText: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
  },
  spacer: {
    height: 20,
  },
});

export default ProfileScreen;
