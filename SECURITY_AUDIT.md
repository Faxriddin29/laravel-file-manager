# Security Audit — alexusmai/laravel-file-manager

**Repo:** `alexusmai/laravel-file-manager`
**Audited commit:** `74bebe3` (HEAD, master; last tag `v3.1.1`)
**Date:** 2026-10-07
**Scope:** Full source audit (`src/`, `config/`, `resources/views/`) + public vulnerability research

This file tracks every issue found, in priority order. Fix them one at a time; check
them off (`[x]`) as you go so the list stays a live work queue.

---

## How to read this report

Each finding has:
- **Status** — whether it's a publicly disclosed CVE (and still present in this code) or a
  new issue found during this audit.
- **Where** — exact file/line.
- **Impact** — what an attacker gets.
- **Fix** — concrete remediation.

---

## 🔴 Critical

### [x] 1. Unauthenticated-by-default access (no auth enforced out of the box)

**Fixed:** Added `FileManagerServiceProvider::warnIfUnprotected()` (called from `boot()`),
which logs a `Log::warning(...)` at boot time if no configured middleware name contains
`"auth"` *and* ACL is disabled — exactly the insecure-by-default combination described
below. This is a warning, not a hard block (middleware names vary too much — `auth`,
`auth:sanctum`, `jwt.auth`, a custom guard — to safely refuse to boot), but it now makes
the risk impossible to miss in logs instead of silently relying on a comment in a config
file. Defaults in `config/file-manager.php` were left unchanged to avoid a silent
breaking change; integrators still need to add `auth`/enable ACL themselves.

**Status:** Design flaw, not a CVE — but the root cause that makes every other issue
remotely exploitable in real deployments.

**Where:** `config/file-manager.php:98` (`'middleware' => ['web']`), `config/file-manager.php:105`
(`'acl' => false`), `src/Requests/RequestValidator.php:18` (`authorize() { return true; }`).

**Impact:** The package ships with only the `web` middleware group (session + CSRF) and
ACL disabled. There is no built-in authentication/authorization check anywhere in the
controller, request validator, or middleware pipeline — it's 100% left to the integrator
to add `auth` (and ACL) themselves. In practice, many real-world deployments forget this,
exposing a full read/write/delete/upload file manager over HTTP to anonymous users. This
is the precondition that turns every bug below into a trivial, unauthenticated compromise.
It also explains why these packages are a recurring target for mass internet scanning.

**Fix:**
- At minimum, document/enforce (e.g. via a service-provider boot check) that `auth` must
  be in the middleware list, or refuse to boot routes without it.
- Turn `acl` on by default, or ship a safer default (`diskList` empty, requiring explicit
  opt-in per disk).
- In *your* app (since you can't change upstream defaults without a PR), audit
  `config/file-manager.php` right now and confirm `auth`/`auth:sanctum`/etc. is present in
  `middleware`, and that the `public` disk doesn't double as your app's document root.

---

### [ ] 2. CVE-2025-56399 — Remote Code Execution via upload + rename extension bypass
**Status:** Confirmed present in this codebase (CVSS 8.8, authenticated).

**Where:** `src/FileManager.php` — `upload()` (lines 141-203) and `rename()` (lines
274-284).

**Impact:** `upload()` checks `getClientOriginalExtension()` against `allowFileTypes`
*only at upload time* (`FileManager.php:160-168`). `rename()` performs **zero**
validation — it just calls `Storage::disk($disk)->move($oldName, $newName)`. An attacker
can:
1. Upload `shell.png` containing `<?php system($_GET['c']); ?>` (passes the extension
   allowlist, or trivially bypasses it entirely since `allowFileTypes` defaults to `[]` —
   "no restrictions", see finding #4).
2. Call `POST /file-manager/rename` to rename `shell.png` → `shell.php`.
3. Request the file directly through its public URL → PHP executes → RCE.

**Fix:**
- In `rename()`, re-validate the new file's extension against `allowFileTypes` (reject
  the rename, or at least reject the extension change, if the new extension isn't
  allowed) — mirror the same check used in `upload()`.
- Better: validate file *content* (MIME sniffing via `finfo`/`getimagesize()` for images,
  not just the client-supplied extension) at upload time, and re-run that validation on
  any rename that changes the extension.
- Regardless of extension allowlists, never allow the `public`/web-served disk root to be
  a directory where the webserver will execute scripts (`.php`, `.phtml`, `.phar`, etc.) —
  add a hard-coded deny-list for executable extensions that cannot be overridden by config.

---

### [x] 3. CVE-2025-65346 — Path Traversal in `unzip` → arbitrary file write (CVSS 9.1)

**Fixed:** `Zip::extractArchive()` now calls `archiveEntriesAreSafe($destination)` before
`extractTo()`, which walks every entry via `getNameIndex()` and rejects the whole archive
if any entry is an absolute path, a Windows drive-letter path, a stream wrapper, or
resolves (via a realpath-independent `canonicalize()`) outside the destination directory.
The `folder` request parameter is now validated the same way (`isSafePathSegment()`,
allowing nested subfolder names but rejecting `..`, absolute paths, and `scheme://`).

**Status:** Confirmed present in this codebase.

**Where:** `src/Services/Zip.php` — `extractArchive()` (lines 156-181).

**Impact:** `extractArchive()` only checks the *`folder`* request parameter for `..` /
`://` (line 164) before calling `$this->zip->extractTo(...)`. It does **not** inspect the
internal entry names of the ZIP file itself. An attacker who can reach `POST
/file-manager/unzip` (trivial if finding #1 applies) can craft a ZIP whose entries contain
`../../../../var/www/html/shell.php` (or absolute paths) and have `ZipArchive::extractTo()`
write them outside the intended disk root — including into the public webroot — leading
directly to RCE.

**Fix:** Before calling `extractTo()`, iterate `$this->zip->statIndex($i)`/`getNameIndex($i)`
for every entry and reject the whole archive if any entry name:
- contains `..` path segments after normalization,
- is an absolute path (starts with `/` or a drive letter),
- resolves (via `realpath`) outside the target extraction directory.

Example pattern:
```php
for ($i = 0; $i < $this->zip->numFiles; $i++) {
    $entry = $this->zip->getNameIndex($i);
    $target = realpath($destDir . '/' . $entry) ?: $destDir . '/' . $entry;
    if (!str_starts_with($target, realpath($destDir) . DIRECTORY_SEPARATOR)) {
        // abort extraction
    }
}
```
Consider extracting entry-by-entry with `ZipArchive::extractTo($dest, [$safeEntries])`
rather than trusting the archive wholesale.

---

### [x] 4. Path Traversal in `zip` creation via the `name` parameter → arbitrary file write (related to CVE-2025-65345, broader than the reported finding)

**Fixed:** `Zip::createArchive()` now rejects the request up front via
`isSafeArchiveName()`, which requires `name` to be a plain `basename()` (no directory
separators, so it can never carry a path at all), reject any `..` sequence, and end in
`.zip`. This closes both the traversal and the "write an arbitrary extension via the
zip-name parameter" angle in one check — `name` can no longer place the new archive
anywhere but inside the already-validated `path`/`disk`.

**Status:** New finding from this audit (same vulnerability class/root cause as the
publicly reported CVE-2025-65345, but via a different, unreported parameter).

**Where:** `src/Services/Zip.php` — `createArchive()` (lines 95-149) and `createName()`
(lines 224-228).

**Impact:** `createArchive()` validates `elements['files']` and `elements['directories']`
for `..` (lines 101-118), but the **destination zip filename** comes from
`$this->request->input('name')` via `createName()`:
```php
return $this->fullPath($this->request->input('path')) . $this->request->input('name');
```
`name` is never checked for `..`, is never passed through Flysystem's path normalizer (it
goes straight into `ZipArchive::open()` using the *native filesystem path* returned by
`Storage::disk($disk)->path()`, which bypasses Flysystem's traversal protection entirely),
and isn't restricted to a `.zip` extension. An attacker can set
`name = "../../../../public/shell.php"` and have `ZipArchive::open()` create that file at
an arbitrary filesystem location. Because `ZipArchive::addFile()` can store file contents
*uncompressed*, the resulting `.php` file's raw bytes contain the literal payload bytes of
any file added to the archive — PHP's interpreter ignores the surrounding ZIP binary
framing and executes any `<?php ... ?>` block found anywhere in the file, so this is a
practical RCE path, not just an arbitrary-write curiosity.

**Fix:**
- Validate `name` the same way `elements` are validated (reject `..`, reject path
  separators entirely — a zip filename should never contain `/`).
- Enforce a `.zip` extension suffix server-side (don't trust the client to supply it).
- Use `basename($name)` before concatenating, and re-derive the destination directory
  solely from the already-validated `path`/`disk`, never from client-supplied filename
  components.

---

## 🟠 High

### [ ] 5. CVE-2025-63307 — Stored XSS via unrestricted HTML/SVG upload, create, and rename (CVSS 8.1)
**Status:** Confirmed present in this codebase.

**Where:** `src/FileManager.php` — `upload()` (160-168), `createFile()` (415-438),
`rename()` (274-284); served back via `preview()` (336-343), `url()` (353-362),
`streamFile()` (477-487), and directly through the disk's public URL.

**Impact:** `allowFileTypes` defaults to `[]` ("no restrictions", `config/file-manager.php:85`),
so by default users can upload/create/rename files to `.html` or `.svg`. These are then
served either directly from the `public` disk (e.g. `storage/app/public/x.svg` → served
verbatim by the webserver with `Content-Type: image/svg+xml` or `text/html`) or via
`preview`/`url`/`streamFile`, with no `Content-Security-Policy`, no `Content-Disposition:
attachment`, and no sanitization. An SVG containing `<script>` or an `.html` file is
rendered inline in the victim's browser in the application's own origin — classic stored
XSS, usable for session/cookie theft, CSRF-token exfiltration, or pivoting to full account
takeover of other file-manager users (including admins, if ACL is misconfigured).

**Fix:**
- Set a sane, restrictive default for `allowFileTypes` (image/doc extensions only; no
  `html`, `htm`, `svg`, `xml`, `js` by default).
- For any file served inline (`preview`, `thumbnails`, `streamFile`, direct disk URL),
  force `Content-Disposition: attachment` for non-image types, and strip/convert SVGs
  (e.g. re-encode through a raster pipeline) rather than serving the original bytes.
- Serve user-uploaded content from a separate origin/subdomain from the main app, or add
  `Content-Security-Policy: sandbox` headers on that path, so any script execution is
  isolated from the primary session/cookies.

---

### [ ] 6. Extension-only upload validation — no content/MIME verification
**Status:** New finding (the root cause enabling #2 and contributing to #5).

**Where:** `src/FileManager.php:159-168` (upload), `src/Requests/RequestValidator.php`
(no file-content validation at all — only `disk`/`path` are validated).

**Impact:** `getClientOriginalExtension()` is purely client-supplied metadata (the
substring after the last `.` in the filename the browser sent) — it has no relationship
to the file's actual content. Even with a non-empty `allowFileTypes` allowlist, this is a
classic "extension allowlist without content verification" bypass: any file can be
uploaded as `photo.jpg` while containing a PHP webshell, a malicious SVG, polyglot
content, etc. Combined with #2 and #5 above, this is the common enabling bug behind both
disclosed CVEs.

**Fix:** Validate actual file content, not just the claimed extension:
- For images: `getimagesize()` / Intervention Image's own decode must succeed, and the
  detected MIME type must match an allowlist.
- For all files: use `finfo_file()`/`$file->getMimeType()` (which inspects magic bytes)
  and cross-check against the extension; reject mismatches.
- Reject any upload whose content contains `<?php`, `<%`, or other active-content
  signatures when the target extension class is "document/image".

---

### [ ] 7. No authoritative server-side allowlist of dangerous/executable extensions
**Status:** New finding.

**Where:** `config/file-manager.php:85` (`allowFileTypes`), `src/FileManager.php:160-168`.

**Impact:** `allowFileTypes` is a single config array that is entirely optional and,
critically, is advisory only — `rename()` and `createFile()`/`paste()` never consult it at
all (see #2). Even where it is consulted, it's a plain string match, so there's nothing
stopping an integrator from accidentally including `php`/`phtml`/`phar`/`cgi` in a
"let's just allow everything the client wants" config, or from the list simply being
empty (the shipped default).

**Fix:** Add a second, hard-coded deny-list of server-executable extensions
(`php`, `php3`-`php8`, `phtml`, `phar`, `cgi`, `pl`, `asp`, `aspx`, `jsp`, `exe`, `sh`,
`.htaccess`, etc.) that is enforced on **every** write path that can affect a file's name
or extension — `upload`, `createFile`, `rename`, `paste`/copy-cut, and zip `extract` —
regardless of what `allowFileTypes` says.

---

## 🟡 Medium

### [ ] 8. `rename`, `paste`, and zip `elements` inputs are not validated by `RequestValidator`
**Status:** New finding.

**Where:** `src/Requests/RequestValidator.php:28-56` — `rules()` only validates `disk` and
`path`. Every other input (`newName`, `oldName`, `items`, `clipboard`, `elements`, `name`,
`folder`) is consumed directly from `$request->input(...)` in `FileManagerController.php`
and `FileManager.php` with no type/shape/content validation at the HTTP-request layer.

**Impact:** Malformed or unexpected types (e.g. `items` not being an array, `clipboard`
missing `disk`/`type` keys) will raise uncaught PHP errors (potential information
disclosure via stack traces if `APP_DEBUG=true`), and — more importantly — pushes all
security-relevant validation (path traversal, extension checks) down into
service/trait code that, as shown in #3/#4, doesn't consistently do it. Validating at the
`FormRequest` boundary is standard Laravel practice and currently skipped entirely for
these fields.

**Fix:** Add explicit validation rules for every input consumed by each route (correct
types, required keys for `clipboard`/`items`/`elements`, and a `string` + no-`..`-segment
rule for anything that becomes a path component).

---

### [ ] 9. `Storage::disk($disk)->path()` bypasses Flysystem's path-traversal protection by design
**Status:** New finding (root cause note for #4; relevant anywhere `->path()` is used).

**Where:** `src/Services/Zip.php:85-88` (`prefixer()`), and anywhere else `->path($path)`
is called with a user-influenced `$path`.

**Impact:** Flysystem v3's local adapter normalizes paths and throws
`PathTraversalDetected` for most write/read operations (`put`, `copy`, `move`, `exists`,
etc.), which is why most of the controller surface is relatively safe against literal
`..` segments. `Storage::disk()->path()`, however, returns a raw native filesystem path
and is **not** routed through that normalizer — it's a deliberate escape hatch Laravel
provides for integrating with non-Flysystem APIs (exactly why `Zip.php` uses it to talk to
`ZipArchive`). The developers were clearly aware of this (hence the manual `..` checks on
`elements` and `folder`), but the coverage is incomplete (see #3, #4).

**Fix:** Treat every use of `->path()` with user-influenced input as a manual-validation
boundary: canonicalize with `realpath()` after concatenation and verify the result is
still a descendant of `realpath(Storage::disk($disk)->path(''))` before using it for any
filesystem operation that doesn't go through Flysystem.

---

### [ ] 10. Download/stream/preview/thumbnail endpoints ACL-exempt granularity gaps when ACL is enabled
**Status:** New finding (defense-in-depth gap, only relevant once ACL is turned on).

**Where:** `src/Middleware/FileManagerACL.php` — `checkContent()` (121-125) requires only
access level `!= 0` (i.e. read-only access level `1` is sufficient) for `fm.preview`,
`fm.thumbnails`, `fm.stream-file`, and `fm.url`, which is correct and intended — but note
that `fm.url` returning a direct, permanent public URL (`FileManager::url()`,
`FileManager.php:353-362`) means once a URL is handed out, ACL is no longer enforced for
subsequent direct requests to that URL (it's served by the webserver/disk driver, not
routed back through this package). For non-public disks this is fine (no public URL
exists), but for the `public` disk this means "read access in the file manager" is
effectively "permanent unauthenticated access to that file," which may be surprising given
ACL is meant to gate access per-user.

**Fix:** Document this clearly (ACL governs the *file manager UI*, not the underlying
storage URL — anyone with the URL can always fetch a `public`-disk file). If
per-user-revocable access is required, don't use the `public` disk / symlinked storage for
ACL'd content — proxy file bytes through an authenticated controller action instead.

---

## 🟢 Informational / hardening

### [ ] 11. Filename slugification is opt-in and off by default
**Where:** `config/file-manager.php:165` (`'slugifyNames' => false`).
Leaving this off means uploaded filenames retain arbitrary user-supplied characters
(spaces, unicode, etc.) — mostly a usability/portability concern, but unusual filenames
(e.g. containing shell metacharacters) could matter if any other tooling shells out based
on stored filenames. Not currently observed in this codebase, but worth enabling by
default for defense-in-depth.

### [ ] 12. No rate limiting / brute-force protection on any route
**Where:** `src/routes.php`, `config/file-manager.php:98`.
No `throttle` middleware is included in the default middleware stack. Combined with
finding #1, an exposed instance can be scraped/bulk-downloaded or have its disk filled via
repeated uploads with no rate limiting. Add `throttle:...` to the default middleware list.

### [ ] 13. `ACL::getAccessLevel()` uses `fnmatch()` for path matching
**Where:** `src/Services/ACLService/ACL.php:48-50`.
`fnmatch()` pattern semantics can surprise (e.g. `*` matches across `/` boundaries,
unlike typical "glob per path segment" expectations), which can cause ACL rules to be
broader than the administrator intended (e.g. a rule meant to scope `folder2/*` could
unintentionally match `folder2-secret/file` depending on exact pattern authored — review
your own `aclRules` carefully against this semantics, it's not a code bug but a sharp
edge). Verify your own `aclRules` in `config/file-manager.php` do not rely on `/`-bounded
glob semantics that `fnmatch()` doesn't provide.

---

## Summary table

| # | Issue | CVE | Severity | Status |
|---|-------|-----|----------|--------|
| 1 | No auth enforced by default | — | Critical (enabler) | Fixed (warning added) |
| 2 | RCE via upload+rename extension bypass | CVE-2025-56399 | Critical (8.8) | Open |
| 3 | Path traversal in unzip → arbitrary write | CVE-2025-65346 | Critical (9.1) | Fixed |
| 4 | Path traversal in zip `name` param → arbitrary write | (unreported, same class as CVE-2025-65345) | Critical | Fixed |
| 5 | Stored XSS via HTML/SVG upload | CVE-2025-63307 | High (8.1) | Open |
| 6 | Extension-only upload validation | — | High | Open |
| 7 | No hard-coded dangerous-extension deny-list | — | High | Open |
| 8 | Missing request validation for most inputs | — | Medium | Open |
| 9 | `->path()` bypasses Flysystem traversal protection | — | Medium | Open |
| 10 | Public-disk URLs bypass ACL after issuance | — | Medium | Open |
| 11 | Slugify filenames off by default | — | Info | Open |
| 12 | No rate limiting | — | Info | Open |
| 13 | `fnmatch()` ACL semantics sharp edge | — | Info | Open |

**Note on upstream status:** As of this audit, CVE-2025-56399, CVE-2025-63307,
CVE-2025-65345, and CVE-2025-65346 all show **no patched version available** upstream.
This repo (HEAD `74bebe3`) still contains all four. Fixes here will need to be applied
locally (and ideally upstreamed as a PR) rather than pulled in via a version bump.

---

## Suggested fix order

1. **#1** (auth/ACL posture) — biggest leverage, blocks remote exploitation of everything else.
2. **#3, #4** (zip/unzip arbitrary write) — most direct path to RCE, same code area, fix together.
3. **#2, #6, #7** (upload/rename extension & content validation) — same root cause, fix together.
4. **#5** (XSS serving) — depends on #6/#7's allowlist work.
5. **#8, #9, #10** — hardening once the critical paths are closed.
6. **#11, #12, #13** — cheap wins, do whenever convenient.