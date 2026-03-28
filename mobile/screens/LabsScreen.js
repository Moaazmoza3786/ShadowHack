import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  FlatList,
} from 'react-native';
import axios from 'axios';

const LabsScreen = ({ navigation }) => {
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchLabs();
  }, [filter]);

  const fetchLabs = async () => {
    try {
      // Mock labs data
      const mockLabs = [
        {
          id: 1,
          title: 'SQL Injection Basics',
          category: 'web',
          difficulty: 'beginner',
          xp_reward: 100,
          duration: '30 min',
          progress: 0,
        },
        {
          id: 2,
          title: 'Network Reconnaissance',
          category: 'network',
          difficulty: 'intermediate',
          xp_reward: 250,
          duration: '45 min',
          progress: 0,
        },
        {
          id: 3,
          title: 'Cryptography Fundamentals',
          category: 'crypto',
          difficulty: 'intermediate',
          xp_reward: 200,
          duration: '60 min',
          progress: 0,
        },
        {
          id: 4,
          title: 'Buffer Overflow Exploit',
          category: 'reverse',
          difficulty: 'advanced',
          xp_reward: 500,
          duration: '90 min',
          progress: 0,
        },
        {
          id: 5,
          title: 'Privilege Escalation',
          category: 'system',
          difficulty: 'advanced',
          xp_reward: 450,
          duration: '75 min',
          progress: 0,
        },
      ];

      setLabs(mockLabs);
    } catch (error) {
      console.error('Error fetching labs:', error);
    } finally {
      setLoading(false);
    }
  };

  const getDifficultyColor = (difficulty) => {
    const colors = {
      beginner: '#00ff88',
      intermediate: '#ffaa00',
      advanced: '#ff3333',
    };
    return colors[difficulty] || '#888';
  };

  const renderLabCard = ({ item }) => (
    <TouchableOpacity
      style={styles.labCard}
      onPress={() => navigation.navigate('Home')}
    >
      <View style={styles.labHeader}>
        <Text style={styles.labTitle}>{item.title}</Text>
        <Text
          style={[
            styles.difficulty,
            { color: getDifficultyColor(item.difficulty) },
          ]}
        >
          {item.difficulty.toUpperCase()}
        </Text>
      </View>

      <View style={styles.labInfo}>
        <View style={styles.infoPill}>
          <Text style={styles.infoText}>⏱️ {item.duration}</Text>
        </View>
        <View style={styles.infoPill}>
          <Text style={styles.infoText}>⭐ {item.xp_reward} XP</Text>
        </View>
      </View>

      <View style={styles.labFooter}>
        <View style={styles.progressBar}>
          <View
            style={[styles.progressFill, { width: `${item.progress}%` }]}
          />
        </View>
        <TouchableOpacity style={styles.startButton}>
          <Text style={styles.startButtonText}>Start Lab →</Text>
        </TouchableOpacity>
      </View>
    </TouchableOpacity>
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
        <Text style={styles.title}>Available Labs</Text>
      </View>

      {/* Filter Tabs */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        style={styles.filterContainer}
      >
        {['all', 'web', 'network', 'crypto', 'reverse'].map((cat) => (
          <TouchableOpacity
            key={cat}
            style={[
              styles.filterTab,
              filter === cat && styles.filterTabActive,
            ]}
            onPress={() => setFilter(cat)}
          >
            <Text
              style={[
                styles.filterText,
                filter === cat && styles.filterTextActive,
              ]}
            >
              {cat.toUpperCase()}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* Labs List */}
      <FlatList
        data={labs}
        renderItem={renderLabCard}
        keyExtractor={(item) => item.id.toString()}
        contentContainerStyle={styles.listContainer}
        scrollEnabled={false}
      />
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
  filterContainer: {
    paddingHorizontal: 16,
    marginBottom: 16,
    maxHeight: 50,
  },
  filterTab: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    marginRight: 8,
    borderRadius: 20,
    backgroundColor: '#1a1f3a',
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  filterTabActive: {
    backgroundColor: '#00ff88',
    borderColor: '#00ff88',
  },
  filterText: {
    color: '#888',
    fontWeight: '600',
    fontSize: 12,
  },
  filterTextActive: {
    color: '#000',
  },
  listContainer: {
    paddingHorizontal: 16,
    paddingBottom: 20,
  },
  labCard: {
    backgroundColor: '#1a1f3a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    borderColor: '#2a2f4a',
    borderWidth: 1,
  },
  labHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12,
  },
  labTitle: {
    flex: 1,
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
  },
  difficulty: {
    fontSize: 10,
    fontWeight: 'bold',
    marginLeft: 8,
  },
  labInfo: {
    flexDirection: 'row',
    marginBottom: 12,
    gap: 8,
  },
  infoPill: {
    backgroundColor: '#0f1321',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 6,
  },
  infoText: {
    fontSize: 12,
    color: '#aaa',
  },
  labFooter: {
    gap: 10,
  },
  progressBar: {
    height: 6,
    backgroundColor: '#0f1321',
    borderRadius: 3,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#00ff88',
  },
  startButton: {
    backgroundColor: '#00ff88',
    paddingVertical: 10,
    borderRadius: 6,
    alignItems: 'center',
  },
  startButtonText: {
    color: '#000',
    fontWeight: 'bold',
    fontSize: 14,
  },
});

export default LabsScreen;
