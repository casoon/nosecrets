import { ansiToHtml } from '@casoon/pages-theme/ansi';
import type { ShowcaseExample } from '@casoon/pages-theme/showcase';

// Real runs of the released binary against the fixtures in captures/usecases/<slug>/
// (see captures/usecases.sh). input.txt holds the files, transcript.ansi the session.
const texts = import.meta.glob<string>('../captures/usecases/*/*.{txt,ansi}', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const read = (slug: string, name: string) => texts[`../captures/usecases/${slug}/${name}`];

const cases = [
  {
    slug: 'leaked-key',
    group: 'Stop a leak',
    title: 'A token and a database password in one commit',
    description:
      'Both files are staged, the hook runs `nosecrets scan --staged`. The commit stops (exit status 1); the report names file, line, rule and a masked preview, never the secret itself.',
    tags: ['scan --staged', 'github-pat', 'postgres-connection-uri', 'exit 1'],
  },
  {
    slug: 'staged-snapshot',
    group: 'Stop a leak',
    title: 'Deleting the line afterwards does not help',
    description:
      'The token is staged, then removed from the working-tree copy. nosecrets reads the staged blob from the Git index, so it still reports what the commit would contain.',
    tags: ['scan --staged', 'git index'],
  },
  {
    slug: 'adopt',
    group: 'Adopt it',
    title: 'Adopt it in a repository that already exists',
    description:
      '`scan --tracked` checks everything Git tracks once. A known old token is accepted by fingerprint and path with `nosecrets ignore`; the entry lives in `.nosecretsignore` and shows up in code review.',
    tags: ['scan --tracked', 'ignore', '.nosecretsignore'],
  },
  {
    slug: 'exceptions',
    group: 'Adopt it',
    title: 'Exceptions on purpose, visible in review',
    description:
      'A documented example carries an inline `@nsi` marker, a fixtures directory is ignored in `.nosecrets.toml`. Only the real staging token is reported.',
    tags: ['@nsi', '.nosecrets.toml', 'ignore paths'],
  },
  {
    slug: 'entropy',
    group: 'Beyond the built-in rules',
    title: 'A token no rule knows',
    description:
      'The entropy check flags long random strings next to names like `TOKEN` or `KEY`. The placeholder `changeme` on the line above is left alone.',
    tags: ['high-entropy-string', 'medium'],
  },
  {
    slug: 'team-rule',
    group: 'Beyond the built-in rules',
    title: 'Your own token format as a rule',
    description:
      'A short TOML file describes the format of an internal token; `--rules` adds it to the built-in ones.',
    tags: ['--rules', 'custom rule'],
  },
  {
    slug: 'json',
    group: 'In scripts and CI',
    title: 'Machine-readable output',
    description:
      '`--format json` prints one array with path, line, column, rule, severity, fingerprint and masked preview, for editors, dashboards and scripts.',
    tags: ['--format json'],
  },
  {
    slug: 'bad-config',
    group: 'In scripts and CI',
    title: 'A typo in the configuration stops the scan',
    description:
      'An unknown key is an error with the allowed names, and the exit status is 2, not 1. A broken configuration can no longer pass as "no findings".',
    tags: ['exit 2', 'strict configuration'],
  },
];

export const examples: ShowcaseExample[] = cases.map(({ slug, ...meta }) => ({
  slug,
  ...meta,
  file: `site/captures/usecases/${slug}/`,
  input: { code: read(slug, 'input.txt').trimEnd(), lang: 'text' },
  output: { html: ansiToHtml(read(slug, 'transcript.ansi')), kind: 'terminal' },
}));
