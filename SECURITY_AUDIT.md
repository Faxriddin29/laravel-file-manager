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

**Follow-up fix (post-review):** the first version logged unconditionally every time
`warnIfUnprotected()` ran — but a service provider's `boot()` runs on *every* HTTP
request and Artisan command for the whole application, not just file-manager routes. On
an install that's still unprotected (exactly the install this warning targets), that
meant a log line on every single request with no de-dup, which is log spam at best and a
disk-pressure risk at worst on anything with real traffic. Throttled via
`Cache::has()`/`Cache::put(..., now()->addDay())` so it logs at most once per day; if the
cache itself is unavailable the check fails open (logs anyway) rather than silently
losing the warning.

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

### [x] 2. CVE-2025-56399 — Remote Code Execution via upload + rename extension bypass

**Fixed:** `rename()` now re-validates the new name before moving the file (skipped for
directories, detected via `Storage::disk($disk)->directoryExists()`): the new extension
must pass `isAllowedExtension()` (hard-coded dangerous-extension denylist + the configured
allowlist) and `basename($newName)` must not be a dangerous filename (`.htaccess`, etc.).
This closes the exact CVE-2025-56399 chain — `shell.png` → rename to `shell.php` is now
rejected with `fileTypeNotAllowed` because `php` is on the denylist, regardless of what
`allowFileTypes` is configured to. See #6/#7 for the shared helper and the upload-side
fix, and #3/#4's note above for the zip-extraction angle of the same root cause.

**Follow-up fix (post-review):** the first version of this fix checked the new extension
against the allowlist on *every* rename, not just when the extension actually changes —
so renaming `notes.txt` to `notes-final.txt` would fail if `txt` wasn't in a configured
`allowFileTypes`, even though nothing about the risk changed. Corrected to only enforce
the allowlist when `strtolower($newExtension) !== strtolower($oldExtension)`; the
dangerous-filename check (`.htaccess`, etc.) still always applies regardless of whether
the extension changed. Verified against both the original CVE chain (still blocked) and
the same-extension-rename case (now allowed) with a standalone test harness.

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
separators, so it can never carry a path at all) and end in `.zip`. This closes both the
traversal and the "write an arbitrary extension via the zip-name parameter" angle in one
check — `name` can no longer place the new archive anywhere but inside the already-
validated `path`/`disk`.

**Follow-up fix (post-review):** the first version also rejected any `name` merely
*containing* the substring `".."` (e.g. `report..final.zip` would have been rejected as a
false positive). Removed that check entirely once I confirmed it's provably redundant
here: `$name !== basename($name)` already guarantees no `/`, so `name` can never be a
multi-segment path, and the mandatory `.zip` suffix means it can never literally equal
`".."`. The same false-positive class existed in `isSafePathSegment()` (used for zip
entries, the `folder` param, and — see below — the `elements` arrays) and in the
pre-existing `elements['files']`/`elements['directories']` traversal checks in
`createArchive()` (substring `strpos($x, '..')`, predating this audit); all three now use
a proper segment-based check (`explode('/', ...)`, reject only a segment that's *exactly*
`".."`), and the `elements` checks were upgraded from a bare `..`-substring test to the
same `isSafePathSegment()` used elsewhere (now also catching absolute paths and stream
wrappers there, which the original check never did — defense-in-depth already covered by
`prefixer()`'s containment check, but tightened for consistency). Verified with 20
standalone test cases covering both the false positives and that real traversal/absolute-
path/stream-wrapper attempts are still rejected.

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

### [x] 5. CVE-2025-63307 — Stored XSS via unrestricted HTML/SVG upload, create, and rename (CVSS 8.1)

**Fixed:** Rather than changing the `allowFileTypes` default (storing HTML/SVG assets is a
legitimate use case for this package, unlike server-executable extensions — see #7), the
fix targets where the actual XSS fires: the endpoints that serve file content *inline* in
the app's own origin. Added `MARKUP_EXTENSIONS`/`isMarkupExtension()` to
`FileTypeGuardTrait` (html, htm, xhtml, shtml, svg, svgz, xml, mhtml, mht) and used it in:
- `streamFile()` — this is the real-world vector: it served any path with
  `Content-Disposition: inline`, including an uploaded `.svg`/`.html`, rendering embedded
  `<script>` in the app's origin. Markup extensions are now forced through
  `Storage::disk()->download()` (attachment) instead of `->response()` (inline); actual
  audio/video streaming is unaffected.
- `preview()` / `thumbnails()` — these already route through Intervention Image's
  decode/encode pipeline (which rasterizes real images, incidentally neutralizing most
  SVG-script content), but now reject markup extensions outright with a `415` rather than
  relying on that side effect across drivers/versions.
- All three responses also now send `X-Content-Type-Options: nosniff` as defense-in-depth
  against MIME-sniffing.

The remaining angle — a direct URL to a `public`-disk file served straight by the
webserver, bypassing this package's controller entirely — is a webserver/hosting concern
outside this package's reach; see #10 for that documented limitation.

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

### [x] 6. Extension-only upload validation — no content/MIME verification

**Fixed:** Added `src/Traits/FileTypeGuardTrait.php`, shared by `FileManager` and `Zip`.
Its `containsExecutableSignature()` streams a file in 8KB chunks (capped at 5MB, with a
10-byte overlap so a signature straddling a chunk boundary isn't missed) and rejects it if
it contains `<?php`, `<?=`, `<%`, or a `<script language="php">` tag, regardless of the
claimed extension. This is now called from `upload()` and `updateFile()` — the two routes
that receive raw file content from the client. (Full MIME-sniffing/`getimagesize()`
validation per-type was considered but the signature scan was chosen as the direct fix for
the disclosed CVE's exact technique — see the note on scope in #7.)

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

### [x] 7. No authoritative server-side allowlist of dangerous/executable extensions

**Fixed:** `FileTypeGuardTrait` adds a hard-coded `DANGEROUS_EXTENSIONS` denylist (`php`
and its variants, `phtml`, `phar`, `cgi`, `pl`, `py`, `rb`, `sh`, `asp`/`aspx`, `jsp`, `exe`,
`bat`, `vbs`, `jar`, …) and a `DANGEROUS_FILENAMES` list for exact server-config filenames
(`.htaccess`, `.htpasswd`, `.user.ini`, `web.config`, `php.ini`) that is enforced
**independently of** `allowFileTypes` via `isAllowedExtension()`/`hasDangerousFilename()`.
It is now checked on every write path that can affect a file's name or extension:
`upload()`, `createFile()`, `updateFile()`, `rename()` (all in `FileManager.php`), and zip
`extract()` (in `Zip::archiveEntriesAreSafe()`, which rejects the whole archive if any
entry would land on disk with a dangerous extension/filename — closing the "upload an
allowed `.zip`, extract a `.php` from inside it" bypass of the upload allowlist). `paste`
(copy/cut) was deliberately left unchanged — it only moves/copies files that already exist
on a managed disk and went through these checks when they were created, so it introduces
no new extension.

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

### [x] 8. `rename`, `paste`, and zip `elements` inputs are not validated by `RequestValidator`

**Fixed:** `RequestValidator::rules()` now merges in `routeSpecificRules()`, which adds
per-route rules keyed off `$this->route()->getName()` (mirroring how
`FileManagerACL::CHECKERS` already maps route names to behavior): `files`/`file` as
required file(s) for upload/update-file, `items.*.path`/`items.*.type` (`Rule::in(['file',
'dir'])`) for delete, `clipboard.disk`/`clipboard.type` (`Rule::in(['copy','cut'])`) for
paste, `oldName`/`newName` for rename, `name` for create-directory/create-file/zip,
`elements`/`elements.files`/`elements.directories` for zip, and `folder` for unzip.
Malformed requests now fail with a normal 422 instead of surfacing as an uncaught
TypeError deeper in the service layer. This doesn't replace the path/extension/traversal
checks added in #2–#7 and #9 (those remain the actual security boundary) — it's a shape/
type validation layer in front of them, catching malformed input earlier and more
predictably.

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

### [x] 9. `Storage::disk($disk)->path()` bypasses Flysystem's path-traversal protection by design

**Fixed:** `Zip::prefixer()` (the only place in the package calling `->path()` with
user-influenced input) now independently verifies the resolved path before returning it:
`isWithinRoot()` canonicalizes both the resolved path and the disk root (string-only,
handles `..`/mixed separators, no filesystem access needed) and asserts the resolved path
is a descendant of the root; separately, if the target already exists, `realpath()` is
also compared against `realpath()` of the root, which catches a symlink planted inside the
disk root pointing outside it (a case the string-only check can't see, since the path
*string* looks perfectly safe while the filesystem resolves it elsewhere). Either check
failing throws, which `createArchive()`/`extractArchive()` now catch and turn into the
same fail-closed `*Failed` event + `false` return used everywhere else in this class. This
is a backstop on top of the already-validated callers from #3/#4 (defense-in-depth against
a future regression or an edge case those checks miss), not a replacement for them.

**Follow-up fix (post-review) — performance:** the extra `path()`/`realpath()` work in
`prefixer()` is cheap per call, but `addDirs()`'s per-file loop was already calling
`fullPath()` (→ `prefixer()`) once *per file* being zipped, purely to recompute an
invariant (the base path length used to compute each file's relative path within the
archive) that never changes across that loop. Combined with the hardened `prefixer()`,
zipping a directory with many files would have done several times more filesystem stat
calls than before. Hoisted that computation out of the loop in `addDirs()` so it's
computed once per `addDirs()` call instead of once per file — same result, no behavior
change, removes the compounding cost.

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

### [x] 10. Download/stream/preview/thumbnail endpoints ACL-exempt granularity gaps when ACL is enabled

**Addressed (documentation):** This is an inherent property of serving files directly from
a public disk, not a code defect this package can fix in `url()` itself — so the fix here
is making the limitation impossible to miss rather than papering over it. Added an
"Important limitations" section to `docs/acl.md` ("ACL does not protect direct storage
URLs") spelling out exactly this behavior and the recommended mitigation (proxy bytes
through an authenticated action instead of relying on a public disk for anything
ACL-sensitive).

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

**Reviewed, left as-is:** `config/file-manager.php:165` (`'slugifyNames' => false`).
Deliberately **not** flipped to `true` by default: unlike #12 below, this changes
user-facing output (stored filenames) for every fresh install, which can break an
integrator's existing assumptions (links built from original filenames, etc.) for a
benefit that's speculative rather than a concrete vulnerability found in this codebase —
no shell-out-on-filename or similar path was found during this audit. Leaving this as an
explicit opt-in (`'slugifyNames' => true` in your published config) is the right call
unless you have a specific reason (e.g. integrating with tooling that's picky about
filenames) to turn it on.

**Where:** `config/file-manager.php:165` (`'slugifyNames' => false`).
Leaving this off means uploaded filenames retain arbitrary user-supplied characters
(spaces, unicode, etc.) — mostly a usability/portability concern, but unusual filenames
(e.g. containing shell metacharacters) could matter if any other tooling shells out based
on stored filenames. Not currently observed in this codebase, but worth enabling by
default for defense-in-depth.

### [x] 12. No rate limiting / brute-force protection on any route

**Fixed:** `config/file-manager.php` default `middleware` is now `['web',
'throttle:120,1']` (120 requests/minute per user), with a comment explaining the number is
a starting point to tune against your actual UI call volume (e.g. a view that loads many
thumbnails at once). This only limits request *rate* — it doesn't change who can access
anything — so it's safe to ship on by default.

**Where:** `src/routes.php`, `config/file-manager.php:98`.
No `throttle` middleware is included in the default middleware stack. Combined with
finding #1, an exposed instance can be scraped/bulk-downloaded or have its disk filled via
repeated uploads with no rate limiting. Add `throttle:...` to the default middleware list.

### [x] 13. `ACL::getAccessLevel()` uses `fnmatch()` for path matching

**Addressed (documentation):** This is how `fnmatch()` works, not a bug to patch around
without changing matching semantics for everyone's existing rules (a real behavior change
with its own risk of silently altering who has access to what). Documented instead, in
the two places someone would actually be looking when authoring a rule: a detailed comment
block directly above `aclRules` in `config/file-manager.php` with concrete
prefix/cross-boundary examples, a matching docblock on `ACL::getAccessLevel()`, and an
"Important limitations" section in `docs/acl.md` (the same place #10's note landed) that
specifically calls out the dynamic-username-as-glob-pattern risk in Example 2's own
`\Auth::user()->name` rule.

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
| 2 | RCE via upload+rename extension bypass | CVE-2025-56399 | Critical (8.8) | Fixed |
| 3 | Path traversal in unzip → arbitrary write | CVE-2025-65346 | Critical (9.1) | Fixed |
| 4 | Path traversal in zip `name` param → arbitrary write | (unreported, same class as CVE-2025-65345) | Critical | Fixed |
| 5 | Stored XSS via HTML/SVG upload | CVE-2025-63307 | High (8.1) | Fixed |
| 6 | Extension-only upload validation | — | High | Fixed |
| 7 | No hard-coded dangerous-extension deny-list | — | High | Fixed |
| 8 | Missing request validation for most inputs | — | Medium | Fixed |
| 9 | `->path()` bypasses Flysystem traversal protection | — | Medium | Fixed |
| 10 | Public-disk URLs bypass ACL after issuance | — | Medium | Documented |
| 11 | Slugify filenames off by default | — | Info | Reviewed, left as-is (see notes) |
| 12 | No rate limiting | — | Info | Fixed |
| 13 | `fnmatch()` ACL semantics sharp edge | — | Info | Documented |

**Note on upstream status:** As of this audit, CVE-2025-56399, CVE-2025-63307,
CVE-2025-65345, and CVE-2025-65346 all show **no patched version available** upstream.
This repo (HEAD `74bebe3`) contained all four prior to this pass. All fixes in this
document were applied locally; consider upstreaming them as a PR rather than waiting for
a version bump.

---

## Suggested fix order (completed)

1. **#1** (auth/ACL posture) — biggest leverage, blocks remote exploitation of everything else. ✅
2. **#3, #4** (zip/unzip arbitrary write) — most direct path to RCE, same code area, fixed together. ✅
3. **#2, #6, #7** (upload/rename extension & content validation) — same root cause, fixed together. ✅
4. **#5** (XSS serving) — built on #6/#7's allowlist work. ✅
5. **#8, #9, #10** — hardening once the critical paths were closed. ✅
6. **#11, #12, #13** — cheap wins. ✅ (#11 reviewed and deliberately left at its default — see its notes)

## What's left

Every tracked finding has been addressed in code or documentation. Two items are worth
revisiting periodically rather than considered permanently closed:
- **#1** is a warning, not an enforced block — re-check `config/file-manager.php`'s
  `middleware`/`acl` settings whenever this package is reconfigured.
- **#11** was a deliberate no-op (default left as shipped) — revisit if this install's
  threat model changes (e.g. filenames ever get passed to shell commands elsewhere in the
  app).

No further action is queued unless new findings come up in a future review.