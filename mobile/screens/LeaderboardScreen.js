import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  FlatList,
  ActivityIndicator,
} from 'react-native';

const LeaderboardScreen = () => {
  const [leaderboard, setLeaderboard] = useState([]);
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState('weekly');

  useEffect(() => {
    fetchLeaderboard();
  }, [period]);

  const fetchLeaderboard = async () => {
    try {
      // Mock leaderboard data
      const mockData = [
        {
          rank: 1,
          username: 'CyberNinja',
          xp: 5420,
          badge: '🥇',
          country: '🇺🇸',
        },
        {
          rank: 2,
          username: 'HackerElite',
          xp: 4980,
          badge: '🥈',
          country: '🇬🇧',
        },
        {
          rank: 3,
          username: 'SecurityPro',
          xp: 4750,
          badge: '🥉',
          country: '🇮🇳',
        },
        {
          rank: 4,
          username: 'EthicalGhost',
          xp: 4320,
          badge: '4️⃣',
          country: '🇨🇦',
        },
        {
          rank: 5,
          username: 'ShadowWalker',
          xp: 4150,
          badge: '5️⃣',
          country: '🇦🇺',
        },
        {
          rank: 6,
          username: 'CodeMaster',
          xp: 3980,
          badge: '6️⃣',
          country: '🇩🇪',
        },
        {
          rank: 7,
          username: 'NetDefender',
          xp: 3850,
          badge: '7️⃣',
          country: '🇫🇷',
        },
        {
          rank: 8,
          username: 'BugHunter77',
          xp: 3720,
          badge: '8️⃣',
          country: '🇯🇵',
        },
      ];

      setLeaderboard(mockData);
    } catch (error) {
      console.error('Error fetching leaderboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const renderRankCard = ({ item }) => (
    <View style={styles.rankCard}>
      <View style={styles.rankLeft}>
        <Text style={styles.badge}>{item.badge}</Text>
        <View style={styles.userInfo}>
          <Text style={styles.username}>{item.username}</Text>
          <Text style={styles.country}>{item.country}</Text>
        </View>
      </View>
      <Text style={styles.xp}>{item.xp} XP</Text>
    </View>
  );

  if (loading) {
    return (
      <View style={styles.container}>
        <ActivityIndicator size="large" color="#00ff88" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Global Leaderboard</Text>
        <Text style={styles.subtitle}>Top hackers worldwide</Text>
      </View>

      {/* Period Selector */}
      <View style={styles.periodContainer}>
        {['weekly', 'monthly', 'alltime'].map((p) => (
          <View
            key={p}
            style={[
              styles.periodButton,
              period === p && styles.periodButtonActive,
            ]}
          >
            <Text
              style={[
                styles.periodText,
                period === p && styles.periodTextActive,
              ]}
            >
              {p === 'alltime' ? 'All Time' : p.charAt(0).toUpperCase() + p.slice(1)}
            </Text>
          </View>
        ))}
      </View>

      {/* Leaderboard List */}
      <FlatList
        data={leaderboard}
        renderItem={renderRankCard}
        keyExtractor={(item) => item.rank.toString()}
        contentContainerStyle={styles.listContainer}
        scrollEnabled={false}
      />

      {/* Info Card */}
      <View style={styles.infoCard}>
        <Text style={styles.infoTitle}>🏆 How it works</Text>
        <Text style={styles.infoText}>
          • Complete labs and challenges to earn XP{'\n'}
          • Top performers are promoted weekly{'\n'}
          • Compete against hackers worldwide
        </Text>
      </View>
    </View>
  );
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
  subtitle: {
    fontSize: 14,
    color: '#888',
    marginTop: 4,
  },
  periodContainer: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    marginBottom: 16,
    gap: 8,
  },
  periodButton: {
    flex: 1,
    paddingVertical: 8,
    borderRadius: 6,
    backgroundColor: '#1a1f3a',
    borderColor: '#2a2f4a',
    borderWidth: 1,
    alignItems: 'center',
  },
  periodButtonActive: {
    backgroundColor: '#00ff88',
    borderColor: '#00ff88',
  },
  periodText: {
    color: '#888',
    fontWeight: '600',
    fontSize: 12,
  },
  periodTextActive: {
    color: '#000',
  },
  listContainer: {
    paddingHorizontal: 16,
    paddingBottom: 20,
  },
  rankCard: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    padding: 14,
    marginBottom: 10,
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  rankLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  badge: {
    fontSize: 24,
    marginRight: 12,
  },
  userInfo: {
    flex: 1,
  },
  username: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#fff',
  },
  country: {
    fontSize: 12,
    color: '#888',
    marginTop: 2,
  },
  xp: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#00ff88',
  },
  infoCard: {
    marginHorizontal: 16,
    marginBottom: 20,
    padding: 14,
    backgroundColor: '#1a1f3a',
    borderRadius: 10,
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  infoTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 8,
  },
  infoText: {
    fontSize: 12,
    color: '#888',
    lineHeight: 18,
  },
});

export default LeaderboardScreen;
