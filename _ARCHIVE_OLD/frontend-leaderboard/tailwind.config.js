/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'cyber-black': '#0a0a0f',
                'cyber-dark': '#12121a',
                'cyber-card': '#1a1a2e',
                'neon-green': '#22c55e',
                'neon-purple': '#a855f7',
                'neon-cyan': '#06b6d4',
            },
            fontFamily: {
                'cairo': ['Cairo', 'sans-serif'],
                'mono': ['JetBrains Mono', 'monospace'],
                'cyber': ['Orbitron', 'sans-serif'],
            },
            backgroundImage: {
                'cyber-grid': "radial-gradient(circle, #1a1a2e 1px, transparent 1px)",
            },
            animation: {
                'glitch': 'glitch 0.5s ease-in-out infinite',
                'scanline': 'scanline 8s linear infinite',
            },
            keyframes: {
                glitch: {
                    '0%, 100%': { transform: 'translate(0)' },
                    '33%': { transform: 'translate(-2px, 2px)' },
                    '66%': { transform: 'translate(2px, -2px)' },
                },
                scanline: {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100%)' },
                }
            }
        },
    },
    plugins: [],
}
