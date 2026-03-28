import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
    plugins: [react()],
    build: {
        outDir: '../dist-leaderboard',
        emptyOutDir: true,
        rollupOptions: {
            output: {
                entryFileNames: `assets/leaderboard.js`,
                chunkFileNames: `assets/[name].js`,
                assetFileNames: `assets/[name].[ext]`
            }
        }
    }
})
