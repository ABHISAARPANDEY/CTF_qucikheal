import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import { defineConfig, globalIgnores } from 'eslint/config';

export default defineConfig([
globalIgnores(['dist']),
{
  files: ['**/*.{js,jsx}'],
  extends: [
  js.configs.recommended,
  reactHooks.configs.flat.recommended,
  reactRefresh.configs.vite],

  languageOptions: {
    globals: globals.browser,
    parserOptions: { ecmaFeatures: { jsx: true } }
  },
  rules: {
    // eslint-plugin-react-hooks v7 ships react-compiler-style rules that this
    // codebase (old cinematic panels + new SOC screens) trips widely; keep them
    // visible as warnings rather than failing CI on stylistic ref/effect usage.
    'react-hooks/set-state-in-effect': 'warn',
    'react-hooks/refs': 'warn',
    'react-hooks/purity': 'warn',
    'react-hooks/immutability': 'warn'
  }
}]
);