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
      website: 'https://nosecrets.casoon.de',
      repo: 'casoon/nosecrets',
      license: 'MIT',
      packages: [
        { label: 'crates.io', href: 'https://crates.io/crates/nosecrets-cli' },
        { label: 'npm', href: 'https://www.npmjs.com/package/@casoon/nosecrets' },
      ],
      mdxComponents: './src/mdx-components.ts',
      docsGroups: {
        'getting-started': 'Getting started',
        guides: 'Guides',
        concepts: 'Concepts',
        reference: 'Reference',
      },
      showcase: './src/showcase.ts',
      showcaseLead:
        'Each example is a real nosecrets run: the files on the left, the session on the right. Open one to see how nosecrets behaves in the situation you are in.',
    }),
  ],
});
