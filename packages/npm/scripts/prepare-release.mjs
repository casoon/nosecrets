#!/usr/bin/env node
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(__dirname, '..');
const vendorDir = path.join(packageDir, 'vendor');
const packageJson = JSON.parse(readFileSync(path.join(packageDir, 'package.json'), 'utf8'));
const version = packageJson.version;
const tag = process.env.NOSECRETS_RELEASE_TAG || `v${version}`;
const repo = process.env.NOSECRETS_RELEASE_REPO || 'casoon/nosecrets';
const baseUrl = process.env.NOSECRETS_RELEASE_BASE_URL || `https://github.com/${repo}/releases/download/${tag}`;
const tmp = mkdtempSync(path.join(tmpdir(), 'nosecrets-release-'));

const targets = [
  {
    asset: 'nosecrets-aarch64-apple-darwin.tar.gz',
    vendorDir: 'npm-darwin-arm64',
    binaryName: 'nosecrets',
    executable: true,
  },
  {
    asset: 'nosecrets-x86_64-apple-darwin.tar.gz',
    vendorDir: 'npm-darwin-x64',
    binaryName: 'nosecrets',
    executable: true,
  },
  {
    asset: 'nosecrets-aarch64-unknown-linux-gnu.tar.gz',
    vendorDir: 'npm-linux-arm64',
    binaryName: 'nosecrets',
    executable: true,
  },
  {
    asset: 'nosecrets-x86_64-unknown-linux-gnu.tar.gz',
    vendorDir: 'npm-linux-x64',
    binaryName: 'nosecrets',
    executable: true,
  },
  {
    asset: 'nosecrets-x86_64-pc-windows-msvc.zip',
    vendorDir: 'npm-win32-x64',
    binaryName: 'nosecrets.exe',
    executable: false,
  },
];

function run(command, args, options = {}) {
  execFileSync(command, args, {
    stdio: 'inherit',
    cwd: packageDir,
    ...options,
  });
}

function download(url, destination) {
  run('curl', ['--fail', '--location', '--silent', '--show-error', url, '--output', destination]);
}

function ensureCleanVendorDir() {
  rmSync(vendorDir, { recursive: true, force: true });
  mkdirSync(vendorDir, { recursive: true });
}

function extractAsset(assetPath, target) {
  const destination = path.join(vendorDir, target.vendorDir);
  mkdirSync(destination, { recursive: true });

  if (assetPath.endsWith('.tar.gz')) {
    run('tar', ['-xzf', assetPath, '-C', destination]);
  } else if (assetPath.endsWith('.zip')) {
    run('unzip', ['-o', '-j', assetPath, '-d', destination]);
  } else {
    throw new Error(`Unsupported asset format: ${assetPath}`);
  }

  const binaryPath = path.join(destination, target.binaryName);
  if (!existsSync(binaryPath)) {
    throw new Error(`Expected binary missing after extraction: ${binaryPath}`);
  }

  if (target.executable) {
    chmodSync(binaryPath, 0o755);
  }
}

function main() {
  console.log(`Preparing @casoon/nosecrets npm package from ${repo} ${tag}`);
  ensureCleanVendorDir();

  for (const target of targets) {
    const assetPath = path.join(tmp, target.asset);
    const url = `${baseUrl}/${target.asset}`;
    console.log(`Downloading ${url}`);
    download(url, assetPath);
    extractAsset(assetPath, target);
  }


  console.log('Vendor directory is ready.');
}

try {
  main();
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
