/* eslint-disable import/no-extraneous-dependencies, import/no-unresolved */
import { defineConfig } from 'eslint/config';
import jest from 'eslint-plugin-jest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import js from '@eslint/js';
import { FlatCompat } from '@eslint/eslintrc';
import prettierPlugin from 'eslint-plugin-prettier';
import eslintConfigPrettier from 'eslint-config-prettier';

const compat = new FlatCompat({
  baseDirectory: path.dirname(fileURLToPath(import.meta.url)),
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});

export default defineConfig([
  {
    extends: compat.extends('airbnb-base'),

    plugins: {
      jest,
    },

    languageOptions: {
      globals: {
        ...jest.environments.globals.globals,
      },

      ecmaVersion: 2020,
      sourceType: 'module',
    },

    rules: {
      'max-len': [2, 180],

      'import/extensions': [
        'error',
        {
          js: 'always',
          json: 'always',
        },
      ],
    },
  },
  eslintConfigPrettier,
  {
    plugins: { prettier: prettierPlugin },
    rules: { 'prettier/prettier': 'error' },
  },
]);
