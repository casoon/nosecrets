---
title: Quickstart
description: Scan the existing Git index once, then inspect every staged change before commit.
order: 2
---

## 1. Establish the baseline

From the root of an existing Git repository, scan every tracked blob in the current index:

```sh
nosecrets scan --tracked
```

This includes committed and staged tracked files. It excludes untracked files and does not inspect
history. Review any findings before enabling the hook.

## 2. Add the pre-commit scan

With [pre-commit](https://pre-commit.com/) or [prek](https://github.com/j178/prek), using the
installed `nosecrets` binary:

```yaml
repos:
  - repo: https://github.com/casoon/nosecrets
    rev: v0.5.1 # a release tag
    hooks:
      - id: nosecrets-system
```

Use `id: nosecrets` instead to have the hook build the binary from source; that needs a Rust
toolchain but no installed `nosecrets`.

With [lefthook](https://lefthook.dev/) (`lefthook.yml`):

```yaml
pre-commit:
  commands:
    nosecrets:
      run: nosecrets scan --staged
```

With [husky](https://typicode.github.io/husky/) (`.husky/pre-commit`) or as a plain
`.git/hooks/pre-commit` script:

```sh
#!/bin/sh
nosecrets scan --staged
```

`--staged` reads the exact blobs selected for the next commit, even when the same files contain
different content in the working tree.

## 3. Handle an intentional value

Every finding includes a stable `nsi_…` fingerprint. Add it interactively:

```sh
nosecrets scan --staged --interactive
```

Or write the fingerprint to `.nosecretsignore`, optionally restricted to a path glob. Commit that
file so the exception remains reviewable. See [Configuration](../configuration/) for alternatives.
