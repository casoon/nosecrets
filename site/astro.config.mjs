// @ts-check
import casoonPages from '@casoon/pages-theme';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://casoon.github.io/nosecrets',
  base: '/nosecrets/',
  integrations: [
    casoonPages({
      name: 'nosecrets',
      description: 'Fast, offline secret scanning for Git pre-commit hooks.',
      repo: 'casoon/nosecrets',
      version: '0.3.8',
      license: 'MIT',
      packages: [
        { label: 'crates.io', href: 'https://crates.io/crates/nosecrets-cli' },
        { label: 'npm', href: 'https://www.npmjs.com/package/@casoon/nosecrets' },
      ],
      docsGroups: {
        'getting-started': 'Getting started',
        reference: 'Reference',
      },
      showcase: false,
    }),
  ],
});
