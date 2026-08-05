# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Secure File Transfer Web Application — a PHP file-sharing system with RBAC, MFA, share links, quotas, at-rest encryption, and abuse protection. Pure PHP + PDO/MySQL; **no Composer, no autoloader, no test framework, no build step**. Dependencies are pulled in with explicit `require_once` calls. Target runtime is Nginx + PHP-FPM + MariaDB/MySQL on Debian/Ubuntu.

> Note: `README.md` documents an older **flat** file layout (`index.php`, `auth.php`, etc. at root). That layout is obsolete — the code was restructured into `app/` + `public/` (see below). Trust the actual tree over the README's "File Structure" section.

## Architecture

Three-tier layout, all under `app/` (kept outside the web root) with thin entry points in `public/` (the web root):

```
public/<page>.php        → thin shim: requires bootstrap, then the matching controller
app/bootstrap.php        → defines APP_BASE / APP_DIR, loads core/config.php
app/src/core/            → config.php (constants, session, access guard), db.php (Database PDO wrapper)
app/src/controllers/     → per-page request handlers (dashboard, login, admin, settings, download, shared, ...)
app/src/services/        → business logic classes: Auth, RBAC, MFAService, FileManager, UserManager, ShareManager, app_settings, security_monitor
app/src/views/           → header.php / footer.php / login_form.php (shared HTML partials)
app/src/support/         → smtp_mailer.php
app/storage/uploads/     → uploaded files (encrypted at rest), never web-accessible
database/sql/schema.sql  → full schema (12 tables)
installs/install.sh      → the operational entry point (install / update / uninstall)
webservers-config/       → secure-ftp.conf (Nginx vhost) + reverse-proxy example
```

**Request flow:** Nginx serves `public/` as document root, routing unknown paths to `public/index.php`. Each `public/<page>.php` is a 2–3 line shim that requires `app/bootstrap.php` then the corresponding `app/src/controllers/<page>.php`. Controllers instantiate service classes (`new Database()`, `new Auth($db)`, etc.), handle the request, and include the views. There is no router/framework — the page-to-controller mapping is 1:1 by filename.

**Access guard:** `config.php` runs a central guard at load time. Any `.php` entry point not listed in the `PUBLIC_ENTRYPOINTS` constant requires an authenticated session (`$_SESSION['user_id']` or `access_code_id`), otherwise redirects to `login.php`. When adding a new publicly reachable page, add it to `PUBLIC_ENTRYPOINTS`. `app/bootstrap.php` then re-validates user-backed sessions against the `users` table on every request (kills the session if the account was deleted/disabled, refreshes the cached role if it changed) so admin demote/disable/delete take effect immediately.
  - **Deployment trap:** `install.sh --update` *preserves* the existing `config.php` (it holds per-install secrets), so code/logic changes made to `config.php` never reach updated servers — put updatable logic in `bootstrap.php` or `src/` files instead, and only add new `define()`s to `config.php` (with a matching retrofit block in the installer's update path).

**Database access:** Always go through the `Database` class in `app/src/core/db.php` (`query`, `fetch`, `fetchAll`, `lastInsertId`) with parameterized queries. `query()` swallows PDO exceptions, logs them via `error_log`, and returns `false` — callers must handle a `false` result. `db.php` also holds the `cleanupExpired*` housekeeping functions that services call opportunistically.

## Key subsystems

- **RBAC** (`services/rbac.php`): static role→permission map for `admin` / `user` / `anonymous`. Use `RBAC::isAuthenticated()`, `RBAC::isAdmin()`, `RBAC::getCurrentRole()`, and permission checks rather than reading `$_SESSION` directly. Views (`header.php`) branch on these.

- **Async file processing** (`services/files.php` → `services/process_file.php`): on upload, `FileManager::spawnProcessor()` shells out via `exec("php process_file.php <id> <algo> &")` to run hashing, duplicate detection, optional ClamAV scan, and AES-256-GCM encryption **in the background**. The `files.processing_status` column (`processing`/`done`/`failed`) tracks progress; the UI polls `getFileProcessingStatus()`. `process_file.php` is **CLI-only** (rejects non-CLI SAPI) and re-bootstraps paths itself. Because PHP-FPM's `PHP_BINARY` is `php-fpm`, `findPhpCliBinary()` searches for a real CLI binary — relevant if uploads "hang" in processing.
  - **Known gap (see GH issues #4-#6):** if `exec()` is disabled (`disable_functions`) or the spawned worker never actually launches, `spawnProcessor()` has no fallback and the file silently sits at `processing_status = 'pending'` forever — there is no cron/health-check that detects or recovers stuck jobs, and the dashboard's JS polls indefinitely with no timeout. If a user reports uploads "stuck processing," check these first before assuming a code regression.
  - **Schema/migration trap (GH issue #3):** `processing_status`/`processing_error` are in `database/sql/schema.sql` but were *not* added to `run_update_db_migrations()` in `installs/install.sh`. Any install that went through `--update` rather than `--fresh` from before the async-processing refactor is missing these columns, which makes every upload fail at the `INSERT` with a generic "Failed to save file information." error. Check `DESCRIBE files;` on affected servers before debugging further upstream.

- **Encryption at rest:** files are stored encrypted under `FILE_ENCRYPTION_KEY` (64 hex chars, set at install). **Never change this key after files exist** — existing files become undecryptable. Download decrypts on the fly in `download.php`.

- **Auth & abuse protection** (`services/auth.php`, `services/security_monitor.php`): login rate limiting via the `login_attempts` table; separate tunable lockout windows for download requests, download failures, share-token brute force, and share-password brute force (all the `*_FAILURE_*` / `*_REQUESTS_*` constants in `config.php`). Suspicious activity is written to `security_audit_events` and surfaced in the admin Settings → Security Events tab.

- **MFA** (`services/mfa.php`): per-user TOTP and/or email codes; `mfa_email_codes` and `user_mfa_settings` tables.

- **App settings** (`services/app_settings.php`, `app_settings` table): runtime DB-stored settings (SMTP config, `base_url`, etc.) editable from the admin Settings page — distinct from the compile-time `define()`s in `config.php`.

- **Reverse-proxy awareness:** `config.php` provides `getProtocol()`, `getHost()`, `getBaseUrl()` which honor `X-Forwarded-*` headers; session `cookie_secure` is set dynamically from forwarded proto. The app is HTTP-only by design — TLS terminates at the reverse proxy.

## Common tasks

There is no build/lint/test tooling. Work with the code directly.

- **Syntax-check a changed file:** `php -l app/src/services/files.php`
- **Run the background processor manually** (debugging stuck uploads): `php app/src/services/process_file.php <file_id> <hash_algorithm>`
- **Install / update / uninstall** (run on the target server, needs root):
  - `sudo ./installs/install.sh` or `--fresh` — full clean install
  - `sudo ./installs/install.sh --update` — update files, preserve uploads/config, run idempotent DB migrations
  - `sudo ./installs/install.sh --uninstall` — remove app (optionally DB)
- **Schema changes:** edit `database/sql/schema.sql` AND add a matching idempotent migration in the update path of `installs/install.sh`, since `--update` must upgrade existing installs without data loss.

## Conventions

- `config.php` ships with placeholder secrets (`CHANGE_THIS_PASSWORD`, `CHANGE_THIS_KEY`); the installer rewrites them. Do not commit real credentials.
- Adding a page = new `public/<name>.php` shim + new `app/src/controllers/<name>.php`; register it in `PUBLIC_ENTRYPOINTS` only if it should be reachable without login.
- New business logic belongs in a `services/` class instantiated by the controller, not inline in the controller or the `public/` shim.
- Nginx blocks direct web access to `*.sql`, `*.md`, dotfiles, and the `/app` path — keep anything sensitive out of `public/`.

## Deployment hosts

See `docs/servers.md` for the app server and Nginx reverse-proxy host details. The live reverse-proxy config on that host is at `/etc/nginx/live/twistar.org/panel.mc.conf`.
