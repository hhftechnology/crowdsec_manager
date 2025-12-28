import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react({
      // Enable React Fast Refresh optimizations
      fastRefresh: true,
      // Optimize JSX runtime
      jsxRuntime: 'automatic',
    })
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    // Optimize build performance
    target: 'esnext',
    minify: 'esbuild',
    sourcemap: true, // Enabled for debugging production issues
    // Increase chunk size warning limit for better chunking
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        // Simplified chunking strategy to avoid dependency loading issues
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            // Core UI utilities that are safe to split
            if (id.includes('lucide-react') || 
                id.includes('class-variance-authority') ||
                id.includes('clsx') || 
                id.includes('tailwind-merge')) {
              return 'ui-utils'
            }

            // Data fetching (standalone)
            if (id.includes('axios')) {
              return 'data'
            }

            // General utilities (standalone)
            if (id.includes('date-fns')) {
              return 'utils'
            }

            // EVERYTHING else from node_modules goes into a single vendor chunk.
            // This ensures React, ReactDOM, and all libraries that depend on them
            // (like Radix UI, TanStack Query, Hook Form, Sonner, etc.)
            // are loaded together, preventing initialization race conditions.
            return 'vendor'
          }
        },
        // Optimize asset naming for better caching
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name?.split('.') || []
          const ext = info[info.length - 1]
          if (/png|jpe?g|svg|gif|tiff|bmp|ico/i.test(ext)) {
            return `assets/images/[name]-[hash][extname]`
          }
          if (/woff2?|eot|ttf|otf/i.test(ext)) {
            return `assets/fonts/[name]-[hash][extname]`
          }
          return `assets/[name]-[hash][extname]`
        },
        chunkFileNames: 'assets/js/[name]-[hash].js',
        entryFileNames: 'assets/js/[name]-[hash].js',
      },
    },
  },
  // Optimize dependencies
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      '@tanstack/react-query',
      'react-hook-form',
      'axios',
      'lucide-react',
      'sonner',
      'cmdk',
      'clsx',
      'tailwind-merge',
      'class-variance-authority'
    ],
  },
})
