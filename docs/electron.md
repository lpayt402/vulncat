# Optional Electron wrapper

## Status

Electron is not implemented in this repository. There is no `desktop/` directory, Electron dependency,
Electron Forge configuration, preload bridge, IPC handler, packaged Windows build, or desktop test suite.

The current product runs in Docker and a browser. This document specifies a proposed
wrapper; a desktop package has not been built or validated.

Electron work requires completion of the core browser validation listed below. Desktop work must not delay, weaken,
or replace the Docker deployment described in [architecture.md](architecture.md) and
[security.md](security.md).

## Proposed behavior

A future wrapper may provide a Windows-first convenience shell that:

- checks whether the configured Vulncat web URL is reachable;
- opens that URL inside a constrained Electron window;
- reports actionable Docker/service diagnostics;
- optionally offers to start the local Compose stack when Docker Desktop is already installed; and
- supports a configurable URL for a centrally hosted Vulncat instance.

It must never silently install Docker, collect scanner credentials, embed a universal account, or make the
browser deployment dependent on Electron.

## Required security baseline

Any future implementation must:

- use Electron Forge;
- set `contextIsolation: true`;
- set `nodeIntegration: false`;
- enable the Chromium sandbox where platform packaging permits;
- expose only narrowly scoped operations through a preload script and `contextBridge`;
- validate every IPC channel, argument, path, URL, and response;
- deny arbitrary remote navigation, new windows, downloads, and permission requests;
- allow only configured HTTP(S) Vulncat origins;
- avoid `shell.openExternal` unless the destination is explicitly allowlisted;
- avoid rendering untrusted HTML with privileged APIs;
- store no Vulncat password, session token, scanner credential, scan file, or database secret;
- avoid telemetry, analytics, auto-update services, and external network calls by default; and
- preserve the server's authentication, authorization, CSRF, audit, and download checks.

The wrapper is not an authorization boundary. The FastAPI service must continue to enforce every permission.

## Proposed directory layout

If authorized after core completion, keep desktop code isolated:

```text
desktop/
  package.json
  forge.config.*
  src/
    main.*
    preload.*
    renderer/
  tests/
```

Do not add desktop dependencies to the browser frontend package or application Python runtime. The wrapper
should consume the deployed web application rather than fork its UI or business logic.

## Service discovery and Docker control

The proposed startup sequence is:

1. validate the configured URL against allowed schemes and host policy;
2. request `/healthz` and `/readyz` with short timeouts;
3. when unavailable, display the URL and diagnostic result;
4. detect Docker Desktop without installing or modifying it;
5. ask the user before starting Compose;
6. invoke a fixed repository/installation-owned launcher with no user-authored shell text;
7. stream bounded, redacted status output; and
8. navigate only after readiness succeeds.

Do not accept arbitrary Compose files, service names, shell commands, or working directories over IPC.
Starting or stopping Docker services is a meaningful local state change and must be explicit.

For a central server URL, the wrapper must not bypass TLS validation. Self-signed certificate support, if ever
required, needs a documented trust workflow rather than disabling certificate checks.

## Session behavior

The future window should use an isolated Electron session partition. Server cookies should remain HttpOnly and
managed by Chromium. The preload API must not expose cookie contents or CSRF/session tokens to Node.

Clearing application data should be a deliberate user action and should clear only the Vulncat partition.
The wrapper should not persist login material in a custom file, registry key, environment variable, or IPC
log.

## Packaging expectations

Windows packaging should produce a versioned artifact with:

- application/version metadata;
- code signing when a trusted signing process is available;
- a documented SHA-256 hash;
- reproducible Forge commands;
- clear install/uninstall behavior;
- no bundled Docker installer;
- no source `.env`, backups, scan fixtures, reports, or secrets; and
- dependency/license inventory.

Auto-update is outside the current design. It must not be introduced without an authenticated update channel,
signature verification, rollback design, and explicit operator policy.

## Desktop validation requirements

A future desktop phase must test:

- unreachable Docker and unreachable web service diagnostics;
- successful local and central URL startup;
- URL allowlisting and blocked arbitrary navigation;
- `contextIsolation=true` and `nodeIntegration=false`;
- preload API surface;
- invalid IPC channel and argument rejection;
- command/path injection attempts;
- denied permission and new-window requests;
- absence of credentials in logs/storage;
- application behavior after server logout/session expiry;
- packaged Windows installation and launch; and
- browser deployment remaining fully functional without the desktop package.

The design document's malicious/invalid IPC test is currently not present because the wrapper has not begun.

## Prerequisites for desktop work

Do not start Electron work until the core completion evidence includes:

- successful clean Docker Compose build/start;
- migrations and readiness;
- secure first-run administration;
- supported imports and identity review;
- host/finding operations;
- durable query-driven export and download;
- security, load, backup/restore, and browser tests; and
- no major browser feature represented by a placeholder.

If a Windows build cannot be produced in the available environment after those checks pass, keep the optional
phase isolated and report the exact packaging blocker. Do not weaken the completed web application to obtain a
desktop artifact.
