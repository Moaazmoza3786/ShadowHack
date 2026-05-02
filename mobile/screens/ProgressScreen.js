import React, { useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  ImageBackground,
  Dimensions,
} from 'react-native';

const { width } = Dimensions.get('window');

const ProgressScreen = () => {
  const [selectedCategory, setSelectedCategory] = useState('overall');

  const categories = [
    { id: 'overall', label: 'Overall', emoji: '📊' },
    { id: 'web', label: 'Web Security', emoji: '🌐' },
    { id: 'network', label: 'Networking', emoji: '🔗' },
    { id: 'crypto', label: 'Cryptography', emoji: '🔐' },
  ];

  const skillLevels = {
    overall: [
      { skill: 'General Knowledge', level: 85, maxLevel: 100 },
      { skill: 'Problem Solving', level: 92, maxLevel: 100 },
      { skill: 'Lab Completion', level: 78, maxLevel: 100 },
      { skill: 'Challenge Speed', level: 65, maxLevel: 100 },
    ],
    web: [
      { skill: 'SQL Injection', level: 95, maxLevel: 100 },
      { skill: 'XSS Attacks', level: 88, maxLevel: 100 },
      { skill: 'CSRF Protection', level: 72, maxLevel: 100 },
      { skill: 'API Security', level: 81, maxLevel: 100 },
    ],
    network: [
      { skill: 'TCP/IP', level: 90, maxLevel: 100 },
      { skill: 'Packet Analysis', level: 84, maxLevel: 100 },
      { skill: 'Routing', level: 76, maxLevel: 100 },
      { skill: 'Firewall Config', level: 68, maxLevel: 100 },
    ],
    crypto: [
      { skill: 'Encryption', level: 89, maxLevel: 100 },
      { skill: 'Hash Functions', level: 86, maxLevel: 100 },
      { skill: 'Public Key Crypto', level: 79, maxLevel: 100 },
      { skill: 'Digital Signatures', level: 73, maxLevel: 100 },
    ],
  };

  const achievements = [
    { emoji: '🔓', title: 'First Crack', description: 'Complete first lab' },
    { emoji: '⚡', title: 'Speed Demon', description: 'Complete lab in under 5 min' },
    { emoji: '🎯', title: 'Perfect Score', description: 'Get 100% on a challenge' },
    { emoji: '🔥', title: '7 Day Streak', description: 'Come back for 7 days' },
    { emoji: '👑', title: 'Top 10', description: 'Reach top 10 leaderboard' },
    { emoji: '💎', title: 'Legendary', description: 'Unlock 5 certifications' },
  ];

  const currentSkills = skillLevels[selectedCategory];
  const averageSkill = currentSkills.reduce((sum, s) => sum + s.level, 0) / currentSkills.length;

  return (
    <ScrollView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Your Progress</Text>
      </View>

      {/* Overall Score */}
      <View style={styles.scoreCard}>
        <View style={styles.scoreCircle}>
          <Text style={styles.scoreValue}>{Math.round(averageSkill)}%</Text>
          <Text style={styles.scoreLabel}>Proficiency</Text>
        </View>
        <View style={styles.scoreInfo}>
          <View style={styles.scoreRow}>
            <Text style={styles.scoreRowLabel}>Labs Completed</Text>
            <Text style={styles.scoreRowValue}>42</Text>
          </View>
          <View style={styles.scoreRow}>
            <Text style={styles.scoreRowLabel}>Certifications</Text>
            <Text style={styles.scoreRowValue}>5</Text>
          </View>
          <View style={styles.scoreRow}>
            <Text style={styles.scoreRowLabel}>Total XP</Text>
            <Text style={styles.scoreRowValue}>12,450</Text>
          </View>
        </View>
      </View>

      {/* Category Selector */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        style={styles.categoryContainer}
      >
        {categories.map((cat) => (
          <TouchableOpacity
            key={cat.id}
            style={[
              styles.categoryButton,
              selectedCategory === cat.id && styles.categoryButtonActive,
            ]}
            onPress={() => setSelectedCategory(cat.id)}
          >
            <Text style={styles.categoryEmoji}>{cat.emoji}</Text>
            <Text
              style={[
                styles.categoryLabel,
                selectedCategory === cat.id && styles.categoryLabelActive,
              ]}
            >
              {cat.label}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* Skills */}
      <View style={styles.skillsContainer}>
        <Text style={styles.sectionTitle}>Skills</Text>
        {currentSkills.map((skill, idx) => (
          <View key={idx} style={styles.skillItem}>
            <View style={styles.skillHeader}>
              <Text style={styles.skillName}>{skill.skill}</Text>
              <Text style={styles.skillLevel}>{skill.level}%</Text>
            </View>
            <View style={styles.skillBar}>
              <View
                style={[
                  styles.skillFill,
                  {
                    width: `${(skill.level / skill.maxLevel) * 100}%`,
                    backgroundColor: getSkillColor(skill.level),
                  },
                ]}
              />
            </View>
          </View>
        ))}
      </View>

      {/* Achievements */}
      <View style={styles.achievementsContainer}>
        <Text style={styles.sectionTitle}>Achievements</Text>
        <View style={styles.achievementGrid}>
          {achievements.map((achievement, idx) => (
            <View key={idx} style={styles.achievementCard}>
              <Text style={styles.achievementEmoji}>{achievement.emoji}</Text>
              <Text style={styles.achievementTitle}>{achievement.title}</Text>
              <Text style={styles.achievementDesc}>{achievement.description}</Text>
            </View>
          ))}
        </View>
      </View>

      <View style={styles.spacer} />
    </ScrollView>
  );
};

const getSkillColor = (level) => {
  if (level >= 90) return '#00ff88';
  if (level >= 75) return '#00ccff';
  if (level >= 60) return '#ffaa00';
  return '#ff6b6b';
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e27',
  },
  header: {
    padding: 20,
    paddingTop: 30,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#fff',
  },
  scoreCard: {
    flexDirection: 'row',
    marginHorizontal: 16,
    marginVertical: 12,
    padding: 20,
    backgroundColor: '#1a1f3a',
    borderRadius: 16,
    borderColor: '#00ff88',
    borderWidth: 2,
    alignItems: 'center',
    gap: 20,
  },
  scoreCircle: {
    width: 140,
    height: 140,
    borderRadius: 70,
    backgroundColor: '#0f1321',
    justifyContent: 'center',
    alignItems: 'center',
    borderColor: '#00ff88',
    borderWidth: 3,
  },
  scoreValue: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#00ff88',
  },
  scoreLabel: {
    fontSize: 12,
    color: '#888',
    marginTop: 4,
  },
  scoreInfo: {
    flex: 1,
    gap: 12,
  },
  scoreRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  scoreRowLabel: {
    fontSize: 12,
    color: '#888',
  },
  scoreRowValue: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
  },
  categoryContainer: {
    paddingHorizontal: 16,
    marginVertical: 12,
    maxHeight: 80,
  },
  categoryButton: {
    paddingHorizontal: 14,
    paddingVertical: 10,
    marginRight: 10,
    borderRadius: 12,
    backgroundColor: '#1a1f3a',
    borderColor: '#2a2f4a',
    borderWidth: 1,
    alignItems: 'center',
    minWidth: 100,
  },
  categoryButtonActive: {
    backgroundColor: '#00ff88',
    borderColor: '#00ff88',
  },
  categoryEmoji: {
    fontSize: 20,
    marginBottom: 4,
  },
  categoryLabel: {
    fontSize: 11,
    color: '#888',
    fontWeight: '600',
  },
  categoryLabelActive: {
    color: '#000',
  },
  skillsContainer: {
    paddingHorizontal: 16,
    marginVertical: 12,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 12,
  },
  skillItem: {
    marginBottom: 16,
  },
  skillHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 6,
  },
  skillName: {
    fontSize: 14,
    fontWeight: '600',
    color: '#fff',
  },
  skillLevel: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#00ff88',
  },
  skillBar: {
    height: 8,
    backgroundColor: '#0f1321',
    borderRadius: 4,
    overflow: 'hidden',
  },
  skillFill: {
    height: '100%',
    borderRadius: 4,
  },
  achievementsContainer: {
    paddingHorizontal: 16,
    marginVertical: 12,
    marginBottom: 30,
  },
  achievementGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  achievementCard: {
    width: (width - 16 * 2 - 8) / 2,
    padding: 12,
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    borderColor: '#2a2f4a',
    borderWidth: 1,
    alignItems: 'center',
  },
  achievementEmoji: {
    fontSize: 32,
    marginBottom: 6,
  },
  achievementTitle: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#fff',
    textAlign: 'center',
  },
  achievementDesc: {
    fontSize: 10,
    color: '#888',
    marginTop: 4,
    textAlign: 'center',
  },
  spacer: {
    height: 20,
  },
});

export default ProgressScreen;
