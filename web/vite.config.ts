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
    sourcemap: false,
    // Increase chunk size warning limit for better chunking
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        // Simplified chunking strategy to avoid dependency loading issues
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            // Put React and all React-dependent libraries in one vendor chunk
            // This prevents the "Cannot read properties of undefined (reading 'useState')" error
            // that occurs when chunks load out of order
            if (
              id.includes('react') ||
              id.includes('react-dom') ||
              id.includes('react-router-dom') ||
              id.includes('@radix-ui/') ||
              id.includes('@tanstack/react-query') ||
              id.includes('react-hook-form')
            ) {
              return 'vendor'
            }

            // Icons and styling
            if (id.includes('lucide-react') || id.includes('class-variance-authority') ||
                id.includes('clsx') || id.includes('tailwind-merge') || id.includes('sonner')) {
              return 'ui-utils'
            }

            // Data fetching
            if (id.includes('axios')) {
              return 'data'
            }

            // Other utilities
            if (id.includes('date-fns') || id.includes('cmdk')) {
              return 'utils'
            }

            // All other node_modules
            return 'libs'
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
      'axios',
      'lucide-react',
      'sonner',
      'clsx',
      'tailwind-merge',
      'class-variance-authority'
    ],
  },
})
