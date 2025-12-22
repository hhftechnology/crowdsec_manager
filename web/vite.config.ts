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
        // Optimized manual chunking strategy
        manualChunks: (id) => {
          // Vendor chunk for core React libraries
          if (id.includes('react') || id.includes('react-dom') || id.includes('react-router-dom')) {
            return 'vendor'
          }
          
          // UI chunk for Radix UI components
          if (id.includes('@radix-ui/')) {
            return 'ui-radix'
          }
          
          // Icons and styling chunk
          if (id.includes('lucide-react') || id.includes('class-variance-authority') || 
              id.includes('clsx') || id.includes('tailwind-merge') || id.includes('sonner')) {
            return 'ui-utils'
          }
          
          // Query and data management
          if (id.includes('@tanstack/react-query') || id.includes('axios')) {
            return 'data'
          }
          
          // Forms and validation
          if (id.includes('react-hook-form') || id.includes('date-fns')) {
            return 'forms'
          }
          
          // Node modules that aren't specifically chunked above
          if (id.includes('node_modules')) {
            return 'vendor-misc'
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
