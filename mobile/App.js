import React, { useEffect } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';

// Screens
import HomeScreen from './screens/HomeScreen';
import LabsScreen from './screens/LabsScreen';
import LeaderboardScreen from './screens/LeaderboardScreen';
import ProfileScreen from './screens/ProfileScreen';
import ProgressScreen from './screens/ProgressScreen';

// Keep the splash screen visible
SplashScreen.preventAutoHideAsync();

const Tab = createBottomTabNavigator();
const Stack = createStackNavigator();

const HomeStack = () => {
  return (
    <Stack.Navigator
      screenOptions={{
        headerStyle: {
          backgroundColor: '#0a0e27',
          borderBottomColor: '#1a1f3a',
          borderBottomWidth: 1,
        },
        headerTintColor: '#00ff88',
        headerTitleStyle: {
          fontWeight: 'bold',
        },
      }}
    >
      <Stack.Screen
        name="HomeTab"
        component={HomeScreen}
        options={{ title: 'ShadowHack' }}
      />
    </Stack.Navigator>
  );
};

const LabsStack = () => {
  return (
    <Stack.Navigator
      screenOptions={{
        headerStyle: {
          backgroundColor: '#0a0e27',
          borderBottomColor: '#1a1f3a',
          borderBottomWidth: 1,
        },
        headerTintColor: '#00ff88',
        headerTitleStyle: {
          fontWeight: 'bold',
        },
      }}
    >
      <Stack.Screen
        name="LabsTab"
        component={LabsScreen}
        options={{ title: 'Labs' }}
      />
    </Stack.Navigator>
  );
};

const ProfileStack = () => {
  return (
    <Stack.Navigator
      screenOptions={{
        headerStyle: {
          backgroundColor: '#0a0e27',
          borderBottomColor: '#1a1f3a',
          borderBottomWidth: 1,
        },
        headerTintColor: '#00ff88',
        headerTitleStyle: {
          fontWeight: 'bold',
        },
      }}
    >
      <Stack.Screen
        name="ProfileTab"
        component={ProfileScreen}
        options={{ title: 'Profile' }}
      />
    </Stack.Navigator>
  );
};

export default function App() {
  useEffect(() => {
    SplashScreen.hideAsync();
  }, []);

  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <NavigationContainer>
        <StatusBar barStyle="light-content" backgroundColor="#0a0e27" />
        <Tab.Navigator
          screenOptions={{
            tabBarActiveTintColor: '#00ff88',
            tabBarInactiveTintColor: '#666',
            tabBarStyle: {
              backgroundColor: '#0a0e27',
              borderTopColor: '#1a1f3a',
              borderTopWidth: 1,
            },
            headerShown: false,
          }}
        >
          <Tab.Screen
            name="Home"
            component={HomeStack}
            options={{
              tabBarLabel: 'Home',
              tabBarIcon: ({ color }) => (
                <Text style={{ color, fontSize: 24 }}>🏠</Text>
              ),
            }}
          />
          <Tab.Screen
            name="Labs"
            component={LabsStack}
            options={{
              tabBarLabel: 'Labs',
              tabBarIcon: ({ color }) => (
                <Text style={{ color, fontSize: 24 }}>🔬</Text>
              ),
            }}
          />
          <Tab.Screen
            name="Progress"
            component={ProgressScreen}
            options={{
              tabBarLabel: 'Progress',
              tabBarIcon: ({ color }) => (
                <Text style={{ color, fontSize: 24 }}>📊</Text>
              ),
            }}
          />
          <Tab.Screen
            name="Leaderboard"
            component={LeaderboardScreen}
            options={{
              tabBarLabel: 'Rankings',
              tabBarIcon: ({ color }) => (
                <Text style={{ color, fontSize: 24 }}>🏆</Text>
              ),
            }}
          />
          <Tab.Screen
            name="Profile"
            component={ProfileStack}
            options={{
              tabBarLabel: 'Profile',
              tabBarIcon: ({ color }) => (
                <Text style={{ color, fontSize: 24 }}>👤</Text>
              ),
            }}
          />
        </Tab.Navigator>
      </NavigationContainer>
    </GestureHandlerRootView>
  );
}

import { Text } from 'react-native';
