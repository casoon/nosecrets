---
title: Overview
description: What nosecrets scans, how its two Git index modes differ, and where its boundary lies.
order: 0
---

nosecrets is an offline CLI for detecting credentials before they enter Git history. It combines
50 built-in rules with high-entropy detection, then applies path filters, allowlists and explicit
ignores before reporting a finding.

## The two Git index scans

- `nosecrets scan --tracked` reads every tracked blob from the current Git index. Run it once when
  adopting nosecrets in an existing repository to establish a baseline.
- `nosecrets scan --staged` reads only blobs changed for the next commit. Run it in the pre-commit
  hook every time.

Both commands inspect index contents rather than working-tree copies. A staged secret cannot be
hidden by editing or deleting the corresponding working-tree file after staging it.

## What it deliberately does not do

nosecrets does not scan Git history, connect to provider APIs, verify whether credentials are
live, or upload source code. Rotate a credential through its provider if it has already been
committed; removing it from the latest revision is not enough.

## How the docs are organised

- **Getting started**: install nosecrets and add the initial and pre-commit scans.
- **Reference**: all CLI switches, configuration and the custom rule format.
