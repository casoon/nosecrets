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

```yaml
repos:
  - repo: local
    hooks:
      - id: nosecrets
        name: nosecrets
        entry: nosecrets scan --staged
        language: system
        pass_filenames: false
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
