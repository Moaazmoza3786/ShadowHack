# Home Page UI Enhancement Plan

## Overview
Enhance the home page UI with cyberpunk theme focusing on:
- Hero Section improvements
- Stats & Metrics visualization
- Interactive elements with animations

---

## Files to Create

### 1. `src/components/ParticleField.jsx`
Canvas-based particle system with:
- Floating particles with code snippets (0x, binary, hex values)
- Mouse interaction - particles gravitate away from cursor
- Connection lines between nearby particles
- Smooth 60fps animation with requestAnimationFrame
- Pulsing opacity animation

```jsx
// Key features:
// - particleCount: number of particles (default: 80)
// - connectionDistance: max distance to draw connection lines (default: 150)
// - mouseRadius: mouse interaction radius (default: 200)
// - showCode: display code snippets on particles (default: true)
```

### 2. `src/components/AnimatedCounter.jsx`
Number counting animation component with:
- Intersection Observer for scroll-triggered animation
- easeOutExpo easing function
- Customizable duration, prefix, suffix, decimals
- Reusable for XP, credits, percentages

```jsx
// Props:
// - value: number to animate to
// - duration: animation duration in ms (default: 2000)
// - prefix/suffix: string to prepend/append
// - decimals: number of decimal places (default: 0)
```

### 3. `src/components/SkillRing.jsx`
Circular SVG progress indicator with:
- Animated stroke-dasharray for fill effect
- Gradient stroke support
- Glow filter effect
- Center label/percentage display
- Multiple sizes

```jsx
// Props:
// - value: current value
// - max: maximum value (default: 100)
// - label: center label text
// - color: primary color
// - size: ring diameter (default: 120)
```

### 4. `src/components/GlitchText.jsx`
Text glitch effect wrapper with:
- Chromatic aberration on hover
- Random glitch flicker animation
- Customizable glitch colors
- Intensity control

```jsx
// Props:
// - children: text content
// - intensity: glitch strength (default: 'medium')
// - color1: first glitch color (default: '#00f2ea')
// - color2: second glitch color (default: '#ff0055')
```

---

## Files to Modify

### 5. `src/components/HeroSection.jsx`

**New imports to add:**
```jsx
import ParticleField from './ParticleField';
import GlitchText from './GlitchText';
import SkillRing from './SkillRing';
import AnimatedCounter from './AnimatedCounter';
```

**Changes to make:**

1. **Replace static background with ParticleField:**
```jsx
// Replace the glow orbs background with:
<ParticleField 
  particleCount={60}
  showCode={true}
  className="opacity-40"
/>
```

2. **Wrap hero title in GlitchText:**
```jsx
<GlitchText intensity="high">
  <span className="block text-primary-500 mb-2">Shadow</span>
  <span className="block underline decoration-accent-500/50 underline-offset-[12px]">Hacking Lab</span>
</GlitchText>
```

3. **Add magnetic button effect:**
- Track mouse position relative to button
- Apply transform translate based on mouse position
- Add spring animation for smooth effect

4. **Add stats preview bar below CTAs:**
```jsx
<div className="flex items-center gap-8 mt-8 px-6 py-4 rounded-2xl bg-white/5 border border-white/10">
  <div className="flex items-center gap-3">
    <div className="w-2 h-2 bg-primary-500 rounded-full animate-pulse" />
    <span className="text-xs text-white/60">XP: <span className="text-white font-black"><AnimatedCounter value={15420} /></span></span>
  </div>
  <div className="h-4 w-px bg-white/20" />
  <div className="flex items-center gap-2">
    <Flame className="text-orange-500" size={14} />
    <span className="text-xs text-white/60">Streak: <span className="text-orange-500 font-black">14</span></span>
  </div>
</div>
```

5. **Enhance floating badges with parallax scroll:**
- Use scroll position to adjust translateY
- Add spring physics for smooth effect

6. **Replace visual card with skill rings:**
```jsx
<div className="grid grid-cols-3 gap-4">
  <SkillRing value={85} max={100} label="Combat" color="#00f2ea" size={80} />
  <SkillRing value={72} max={100} label="Intel" color="#ff0055" size={80} />
  <SkillRing value={93} max={100} label="Tech" color="#22c55e" size={80} />
</div>
```

### 6. `src/components/EnhancedStatCard.jsx`

**New imports:**
```jsx
import AnimatedCounter from './AnimatedCounter';
import SkillRing from './SkillRing';
```

**Changes:**

1. **Add sparkline chart SVG:**
```jsx
// Add inside card, below the value
<div className="h-12 mt-4 relative">
  <svg className="w-full h-full" preserveAspectRatio="none">
    <defs>
      <linearGradient id="gradient" x1="0%" y1="0%" x2="0%" y2="100%">
        <stop offset="0%" stopColor={color} stopOpacity="0.3" />
        <stop offset="100%" stopColor={color} stopOpacity="0" />
      </linearGradient>
    </defs>
    <path
      d={`M 0 ${generateSparklinePath()}`}
      fill="url(#gradient)"
      stroke={color}
      strokeWidth="2"
    />
  </svg>
</div>
```

2. **Add SkillRing behind icon:**
```jsx
<div className="relative">
  <SkillRing 
    value={progressValue} 
    max={100} 
    size={56} 
    color={color}
    className="absolute inset-0 opacity-30"
  />
  <div className="w-14 h-14 rounded-2xl flex items-center justify-center">
    <Icon size={24} className={colors.text} />
  </div>
</div>
```

3. **Replace static value with AnimatedCounter:**
```jsx
<AnimatedCounter value={value} duration={2000} />
```

4. **Add hover micro-animations:**
- Scale icon on hover
- Increase glow intensity
- Animate sparkline path

### 7. `src/pages/Dashboard.jsx`

**Changes:**

1. **Add staggered reveal animations with Framer Motion:**
```jsx
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2
    }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 }
};
```

2. **Wrap sections in motion containers:**
```jsx
<motion.section
  variants={containerVariants}
  initial="hidden"
  animate="visible"
>
  {stats.map((stat, i) => (
    <motion.div key={i} variants={itemVariants}>
      <StatCard {...stat} />
    </motion.div>
  ))}
</motion.section>
```

3. **Add mouse-following glow effect:**
```jsx
const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

useEffect(() => {
  const handleMouseMove = (e) => {
    setMousePosition({ x: e.clientX, y: e.clientY });
  };
  window.addEventListener('mousemove', handleMouseMove);
  return () => window.removeEventListener('mousemove', handleMouseMove);
}, []);

// In JSX:
<div 
  className="fixed pointer-events-none w-96 h-96 rounded-full blur-[150px] opacity-10"
  style={{
    background: `radial-gradient(circle, var(--color-primary-500) 0%, transparent 70%)`,
    transform: `translate(${mousePosition.x - 192}px, ${mousePosition.y - 192}px)`
  }}
/>
```

### 8. `src/index.css`

**New keyframe animations to add:**

```css
/* Floating animation for decorative elements */
@keyframes float {
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-20px); }
}

/* Pulsing glow effect */
@keyframes pulse-glow {
  0%, 100% { 
    box-shadow: 0 0 20px rgba(0, 242, 234, 0.3);
    opacity: 1;
  }
  50% { 
    box-shadow: 0 0 40px rgba(0, 242, 234, 0.5);
    opacity: 0.8;
  }
}

/* Glitch hover effect */
@keyframes glitch-hover {
  0% { transform: translate(0); }
  20% { transform: translate(-2px, 2px); }
  40% { transform: translate(-2px, -2px); }
  60% { transform: translate(2px, 2px); }
  80% { transform: translate(2px, -2px); }
  100% { transform: translate(0); }
}

/* Count up animation for numbers */
@keyframes counter-up {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Skill ring fill animation */
@keyframes skill-ring-fill {
  from { stroke-dashoffset: 314; }
  to { stroke-dashoffset: var(--dash-offset); }
}

/* Magnetic button hover */
@keyframes magnetic-pull {
  0% { transform: translate(0, 0); }
  100% { transform: translate(var(--mx), var(--my)); }
}

/* Particle flicker */
@keyframes particle-flicker {
  0%, 100% { opacity: 0.3; }
  50% { opacity: 0.7; }
}

/* Utility classes */
.animate-float {
  animation: float 6s ease-in-out infinite;
}

.animate-pulse-glow {
  animation: pulse-glow 2s ease-in-out infinite;
}

.animate-glitch-hover:hover {
  animation: glitch-hover 0.3s ease-in-out;
}

.animate-counter {
  animation: counter-up 0.5s ease-out forwards;
}

.animate-skill-ring {
  animation: skill-ring-fill 1.5s ease-out forwards;
}

/* Magnetic button class */
.magnetic-btn {
  transition: transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94);
}

.magnetic-btn:hover {
  --mx: calc(var(--mouse-x) * 0.2);
  --my: calc(var(--mouse-y) * 0.2);
}
```

---

## Implementation Order

1. **Create utility components first** (no dependencies):
   - AnimatedCounter.jsx
   - SkillRing.jsx
   - GlitchText.jsx
   - ParticleField.jsx

2. **Modify existing components**:
   - EnhancedStatCard.jsx
   - HeroSection.jsx

3. **Update page layout**:
   - Dashboard.jsx

4. **Add CSS animations**:
   - index.css

---

## Testing Checklist

- [ ] Particles animate smoothly at 60fps
- [ ] AnimatedCounter triggers on scroll into view
- [ ] SkillRing fills with animation
- [ ] GlitchText effect works on hover
- [ ] HeroSection shows all new elements
- [ ] StatCards display sparklines
- [ ] Mouse glow follows cursor
- [ ] All animations are performant (no jank)
- [ ] Mobile responsive (/animations disabled or simplified)

---

## Notes

- All animations use CSS transforms and opacity for GPU acceleration
- Canvas animations use requestAnimationFrame for smooth 60fps
- Scroll animations use Intersection Observer for performance
- Motion preferences should be respected (prefers-reduced-motion)