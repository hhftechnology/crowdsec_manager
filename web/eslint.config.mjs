import js from '@eslint/js'
import { FlatCompat } from '@eslint/eslintrc'
import reactRefresh from 'eslint-plugin-react-refresh'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
})

export default [
  {
    ignores: ['dist'],
  },
  {
    plugins: {
      'react-refresh': reactRefresh,
    },
  },
  ...compat.config({
    env: { browser: true, es2020: true },
    extends: [
      'eslint:recommended',
      'plugin:@typescript-eslint/recommended',
      'plugin:react-hooks/recommended',
    ],
    parser: '@typescript-eslint/parser',
    rules: {
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
      'react-hooks/immutability': 'off',
      'react-hooks/refs': 'off',
      'react-hooks/set-state-in-effect': 'off',
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
          'react-refresh/only-export-components': 'off',
        },
      },
      {
        files: ['src/components/common/**/*.{ts,tsx}'],
        rules: {
          'react-refresh/only-export-components': 'off',
        },
      },
    ],
  }),
]
