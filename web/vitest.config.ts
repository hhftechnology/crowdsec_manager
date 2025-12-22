/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    watch: false,
    reporter: 'verbose',
    // Force non-interactive mode
    passWithNoTests: true,
    // Disable coverage for faster runs
    coverage: {
      enabled: false
    },
    // Set timeout for property-based tests
    testTimeout: 30000,
    // Disable file watching
    watchExclude: ['**/node_modules/**', '**/dist/**'],
  },
})