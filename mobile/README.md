# ShadowHack Mobile App

React Native mobile application for the ShadowHack cybersecurity education platform using Expo.

## Features

- 📊 **Dashboard** - View XP, level, streak, and daily missions
- 🔬 **Labs** - Browse and start security labs on mobile
- 📈 **Progress Tracking** - View skill levels and achievements
- 🏆 **Leaderboards** - Compete globally in real-time rankings
- 👤 **Profile Management** - Certifications, notifications, account settings

## Technology Stack

- **React Native** 0.74.0 - Cross-platform mobile framework
- **Expo** 51.0.0 - Managed React Native platform
- **React Navigation** 6.x - Navigation framework
- **Zustand** - State management
- **Axios** - HTTP client
- **React Native Reanimated** - Smooth animations

## Setup

### Prerequisites
- Node.js 18+ and npm/yarn
- Expo CLI: `npm install -g expo-cli`
- iOS Simulator (macOS) or Android Emulator (Windows/Mac/Linux)
- Expo Go mobile app (for quick testing)

### Installation

```bash
cd mobile
npm install
```

### Running the App

**Development:**
```bash
npm start
```

**On Android Emulator:**
```bash
npm run android
```

**On iOS Simulator (macOS only):**
```bash
npm run ios
```

**Web Version:**
```bash
npm run web
```

**On Expo Go (Mobile):**
1. Install Expo Go from App Store/Play Store
2. Run `npm start`
3. Scan the QR code with Expo Go

## Project Structure

```
mobile/
├── App.js                 # Main app entry point with navigation
├── app.json              # Expo app configuration
├── package.json          # Dependencies and scripts
├── screens/
│   ├── HomeScreen.js     # Dashboard with stats and daily missions
│   ├── LabsScreen.js     # Browse and start labs
│   ├── ProgressScreen.js # Skill tracking and achievements
│   ├── LeaderboardScreen.js # Global rankings
│   └── ProfileScreen.js   # User profile and settings
├── components/           # Reusable UI components (future)
├── utils/               # Helper functions and API clients (future)
└── assets/              # Icons, images, splash screen
```

## Key Screens

### 1. Home Screen
- User greeting with dynamic XP/level display
- Quick action buttons (Start Lab, View Rankings)
- Daily mission progress tracker
- Recent activity feed

### 2. Labs Screen
- Browse available security labs
- Filter by category (Web, Network, Crypto, Reverse)
- Lab difficulty indicators
- XP rewards and time estimates
- Progress tracking

### 3. Progress Screen
- Skill proficiency visualization
- Category-specific skill breakdown
- Overall proficiency percentage
- Achievement badges and tracking

### 4. Leaderboard Screen
- Global rankings by period (weekly/monthly/all-time)
- Player stats with country flags
- Top 10 highlights
- Your rank position

### 5. Profile Screen
- User profile with bio
- Certification status (verified/pending/in-progress)
- Notification preferences
- Account settings
- Logout functionality

## API Integration

The app connects to the backend APIs:

```
GET /api/user/profile              # User data
GET /api/user/stats               # User statistics
GET /api/labs                      # Available labs
POST /api/labs/start/<id>         # Start a lab
GET /api/user/progress            # Progress data
GET /api/leaderboards/global-<period>  # Leaderboard data
GET /api/marketplace/my-certificates   # User certs
```

## Animations & UI

- **Framer Motion-style animations** using React Native Reanimated
- **Dark theme** consistent with web app cyberpunk aesthetic
- **Neon colors** - Lime green (#00ff88), cyan (#00ccff), pink (#ff00ff)
- **Smooth transitions** between screens
- **Gesture support** for swipe navigation

## Performance Considerations

- Lazy loading of screens with React Navigation
- FlatList for efficient list rendering
- Memoized components to prevent unnecessary re-renders
- Offline support with async storage (future)
- Image caching with Expo Image Cache

## Future Enhancements

- [ ] Offline mode with sync
- [ ] Push notifications
- [ ] Video tutorials
- [ ] Real-time chat
- [ ] Lab streaming
- [ ] Achievement system UI
- [ ] Dark/Light theme toggle
- [ ] Biometric authentication
- [ ] App-exclusive mini-games
- [ ] ARCore lab visualization

## Building for Production

### iOS
```bash
eas build --platform ios
```

### Android
```bash
eas build --platform android
```

### Web
```bash
npm run web
```

## Troubleshooting

**Issue:** Port 19000 already in use
```bash
# Use different port
npx expo start --port 19001
```

**Issue:** Module not found errors
```bash
rm -rf node_modules .expo
npm install
```

**Issue:** Expo Go app crashes
```bash
# Clear cache and restart
npm start -- --clear
```

## License

Part of ShadowHack platform. See main repository for license details.

## Contributing

Mobile app development follows the same contribution guidelines as the main ShadowHack project.
