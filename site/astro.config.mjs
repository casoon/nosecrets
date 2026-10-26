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
      tagline: 'Offline secret scanner for pre-commit',
      repo: 'casoon/nosecrets',
      license: 'MIT',
      packages: [
        { label: 'crates.io', href: 'https://crates.io/crates/nosecrets-cli' },
        { label: 'npm', href: 'https://www.npmjs.com/package/@casoon/nosecrets' },
      ],
      mdxComponents: './src/mdx-components.ts',
      docsGroups: {
        'getting-started': 'Getting started',
        concepts: 'Concepts',
        reference: 'Reference',
      },
      showcase: false,
    }),
  ],
});
