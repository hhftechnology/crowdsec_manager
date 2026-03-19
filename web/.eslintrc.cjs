module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
    '@typescript-eslint/no-explicit-any': 'off',

    // Ban direct useEffect — use useMountEffect, React Query, or derived state instead.
    'no-restricted-imports': [
      'error',
      {
        paths: [
          {
            name: 'react',
            importNames: ['useEffect'],
            message:
              'Direct useEffect is banned. Use useMountEffect() for DOM setup, useQuery/useMutation for data, inline computation for derived state, or event handlers for user actions.',
          },
        ],
      },
    ],
    'no-restricted-syntax': [
      'error',
      {
        selector: "CallExpression[callee.name='useEffect']",
        message:
          'Direct useEffect is banned. Use useMountEffect() from @/hooks/useMountEffect for one-time DOM setup.',
      },
      {
        selector:
          "CallExpression[callee.object.name='React'][callee.property.name='useEffect']",
        message:
          'Direct React.useEffect is banned. Use useMountEffect() from @/hooks/useMountEffect.',
      },
    ],
  },
  overrides: [
    // Approved useEffect zones: hooks (abstraction layer), shadcn/ui primitives (generated), contexts
    {
      files: [
        'src/hooks/**/*.{ts,tsx}',
        'src/components/ui/**/*.{ts,tsx}',
        'src/components/ThemeProvider.tsx',
        'src/contexts/**/*.{ts,tsx}',
      ],
      rules: {
        'no-restricted-imports': 'off',
        'no-restricted-syntax': 'off',
        // These files intentionally export utilities/hooks alongside components
        'react-refresh/only-export-components': 'off',
      },
    },
    // Common components intentionally export utility functions alongside components
    {
      files: ['src/components/common/**/*.{ts,tsx}'],
      rules: {
        'react-refresh/only-export-components': 'off',
      },
    },
  ],
}
