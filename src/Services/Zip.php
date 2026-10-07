<?php

namespace Alexusmai\LaravelFileManager\Services;

use Alexusmai\LaravelFileManager\Events\UnzipCreated;
use Alexusmai\LaravelFileManager\Events\UnzipFailed;
use Alexusmai\LaravelFileManager\Events\ZipCreated;
use Alexusmai\LaravelFileManager\Events\ZipFailed;
use Alexusmai\LaravelFileManager\Traits\FileTypeGuardTrait;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use RecursiveIteratorIterator;
use RecursiveDirectoryIterator;
use ZipArchive;

class Zip
{
    use FileTypeGuardTrait;

    protected $zip;
    protected $request;
    //protected $pathPrefix;

    /**
     * Zip constructor.
     *
     * @param  ZipArchive  $zip
     * @param  Request  $request
     */
    public function __construct(ZipArchive $zip, Request $request)
    {
        $this->zip = $zip;
        $this->request = $request;
        //$this->pathPrefix = Storage::disk($request->input('disk'))->path();
            //->getDriver()
            //->getAdapter()
            //->getPathPrefix();
    }

    /**
     * Create new zip archive
     *
     * @return array
     */
    public function create(): array
    {
        if ($this->createArchive()) {
            return [
                'result' => [
                    'status'  => 'success',
                    'message' => null,
                ],
            ];
        }

        return [
            'result' => [
                'status'  => 'warning',
                'message' => 'zipError',
            ],
        ];
    }

    /**
     * Extract
     *
     * @return array
     */
    public function extract(): array
    {
        if ($this->extractArchive()) {
            return [
                'result' => [
                    'status'  => 'success',
                    'message' => null,
                ],
            ];
        }

        return [
            'result' => [
                'status'  => 'warning',
                'message' => 'zipError',
            ],
        ];
    }

    /**
     * Resolve $path to a native filesystem path via Storage::path().
     *
     * Storage::path() bypasses Flysystem's own path normalizer (which
     * is what rejects ".." traversal on put/copy/move/exists/...) -
     * it just concatenates the disk root with $path. Everywhere in
     * this class that calls this method already validates $path
     * first (isSafePathSegment(), isSafeArchiveName(), or the
     * RequestValidator-checked "path" input), but this is a
     * defense-in-depth backstop: it independently asserts the
     * resolved path stays inside the disk root, and - for anything
     * that already exists - that its *real* (symlink-resolved)
     * location does too, since a string check alone can't catch a
     * symlink planted inside the disk root pointing elsewhere.
     *
     * @param  string  $path
     *
     * @return string
     *
     * @throws \RuntimeException  if the resolved path escapes the disk root
     */
    protected function prefixer($path): string
    {
        $disk     = Storage::disk($this->request->input('disk'));
        $resolved = $disk->path($path);
        $root     = $disk->path('');

        if (!$this->isWithinRoot($resolved, $root)) {
            throw new \RuntimeException('Resolved path escapes the disk root.');
        }

        $realResolved = realpath($resolved);
        $realRoot     = realpath($root);

        if ($realResolved && $realRoot && !$this->isWithinRoot($realResolved, $realRoot)) {
            throw new \RuntimeException('Resolved path escapes the disk root.');
        }

        return $resolved;
    }

    /**
     * @param  string  $path
     * @param  string  $root
     *
     * @return bool
     */
    protected function isWithinRoot(string $path, string $root): bool
    {
        $path = $this->canonicalize($path);
        $root = $this->canonicalize($root);

        return $path === $root || str_starts_with($path, $root.'/');
    }

    /**
     * Create zip archive
     *
     * @return bool
     */
    protected function createArchive(): bool
    {
        // elements list
        $elements = $this->request->input('elements');

        // the new archive's filename must be a plain name, not a path
        if (!$this->isSafeArchiveName($this->request->input('name'))) {
            event(new ZipFailed($this->request));
            return false;
        }

        // Check files for traversal/absolute paths/stream wrappers -
        // isSafePathSegment() rejects a literal ".." path segment
        // without false-positiving on a filename that merely contains
        // ".." (e.g. "report..final.txt")
        if (isset($elements['files']) && is_array($elements['files'])) {
            foreach ($elements['files'] as $file) {
                if (!$this->isSafePathSegment($file, true)) {
                    event(new ZipFailed($this->request));
                    return false;
                }
            }
        }

        // Check directories for traversal/absolute paths/stream wrappers
        if (isset($elements['directories']) && is_array($elements['directories'])) {
            foreach ($elements['directories'] as $directory) {
                if (!$this->isSafePathSegment($directory, true)) {
                    event(new ZipFailed($this->request));
                    return false;
                }
            }
        }

        try {
            // create or overwrite archive
            if ($this->zip->open(
                    $this->createName(),
                    ZIPARCHIVE::OVERWRITE | ZIPARCHIVE::CREATE
                ) === true
            ) {
                if (isset($elements['files']) && $elements['files']) {
                    foreach ($elements['files'] as $file) {
                        $this->zip->addFile(
                            $this->prefixer($file),
                            basename($file)
                        );
                    }
                }

                if (isset($elements['directories']) && $elements['directories']) {
                    $this->addDirs($elements['directories']);
                }

                $this->zip->close();

                event(new ZipCreated($this->request));

                return true;
            }
        } catch (\RuntimeException $exception) {
            // a resolved path escaped the disk root - see prefixer()
        }

        event(new ZipFailed($this->request));

        return false;
    }

    /**
     * Archive extract
     *
     * @return bool
     */
    protected function extractArchive(): bool
    {
        // extract to new folder
        $folder = $this->request->input('folder');

        if ($folder && !$this->isSafePathSegment($folder, true)) {
            event(new UnzipFailed($this->request));
            return false;
        }

        try {
            $zipPath  = $this->prefixer($this->request->input('path'));
            $rootPath = dirname($zipPath);

            $destination = $folder ? $rootPath.'/'.$folder : $rootPath;

            if ($this->zip->open($zipPath) === true) {
                // guard against Zip Slip - reject the archive if any entry
                // would extract outside the destination directory
                if (!$this->archiveEntriesAreSafe($destination)) {
                    $this->zip->close();
                    event(new UnzipFailed($this->request));
                    return false;
                }

                $this->zip->extractTo($destination);
                $this->zip->close();

                event(new UnzipCreated($this->request));

                return true;
            }
        } catch (\RuntimeException $exception) {
            // a resolved path escaped the disk root - see prefixer()
        }

        event(new UnzipFailed($this->request));

        return false;
    }

    /**
     * Check that every entry in the currently opened archive would
     * extract to a location inside $destination, and that none of
     * them has a dangerous extension or filename. Protects against
     * "Zip Slip" (entries using ".." segments or absolute paths to
     * write outside the intended directory) as well as using the
     * extraction feature to smuggle in executable files that would
     * never have been accepted through the regular upload checks.
     *
     * @param  string  $destination
     *
     * @return bool
     */
    protected function archiveEntriesAreSafe(string $destination): bool
    {
        $destination = $this->canonicalize($destination);

        for ($i = 0; $i < $this->zip->numFiles; $i++) {
            $entry = $this->zip->getNameIndex($i);

            if ($entry === false || !$this->isSafePathSegment($entry, true)) {
                return false;
            }

            // directory entries end with "/" - no extension to check
            if (!str_ends_with($entry, '/')
                && ($this->hasDangerousExtension(pathinfo($entry, PATHINFO_EXTENSION))
                    || $this->hasDangerousFilename(basename($entry)))
            ) {
                return false;
            }

            $targetDir = $this->canonicalize($destination.'/'.dirname($entry));

            // the entry's resolved parent directory must stay inside
            // the destination (dirname('file.txt') === '.', which is fine)
            if ($targetDir !== $destination
                && !str_starts_with($targetDir, $destination.'/')
            ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate a path segment supplied by the client (a "folder" name
     * for extraction, a raw zip entry name, or - via createArchive() -
     * an existing file/directory path being added to a new archive).
     * Rejects traversal (a "../segment" or "segment/..", not merely a
     * name that happens to *contain* ".." - e.g. "report..final.txt"
     * is a perfectly ordinary filename, not a traversal attempt),
     * absolute paths, Windows drive letters, and stream wrappers.
     *
     * @param  mixed  $value
     * @param  bool   $allowNestedPaths
     *
     * @return bool
     */
    protected function isSafePathSegment($value, bool $allowNestedPaths = false): bool
    {
        if (!is_string($value) || $value === '') {
            return false;
        }

        $normalized = str_replace('\\', '/', $value);

        if (str_contains($normalized, '://')) {
            return false;
        }

        // reject absolute paths (unix) and drive letters (windows)
        if (str_starts_with($normalized, '/') || preg_match('/^[A-Za-z]:/', $normalized)) {
            return false;
        }

        $segments = explode('/', $normalized);

        if (!$allowNestedPaths && count($segments) > 1) {
            return false;
        }

        foreach ($segments as $segment) {
            if ($segment === '..') {
                return false;
            }
        }

        return true;
    }

    /**
     * Resolve a path to its canonical absolute form, without requiring
     * it to exist on disk (unlike realpath()), so it can be used to
     * validate destinations before they are created.
     *
     * @param  string  $path
     *
     * @return string
     */
    protected function canonicalize(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $segments = [];

        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }

        $prefix = str_starts_with($path, '/') ? '/' : '';

        return rtrim($prefix.implode('/', $segments), '/');
    }

    /**
     * Validate the name of the archive to be created. Must be a plain
     * filename with a .zip extension, so it can't be used to write
     * outside the target directory or with a dangerous extension.
     *
     * No separate ".." check is needed here: $name !== basename($name)
     * already rejects anything containing "/" (so it can never be a
     * multi-segment path), and the mandatory ".zip" suffix means it
     * can never literally equal "..". A name like "report..final.zip"
     * is a perfectly ordinary filename and must not be rejected.
     *
     * @param  mixed  $name
     *
     * @return bool
     */
    protected function isSafeArchiveName($name): bool
    {
        if (!is_string($name) || $name === '' || $name !== basename($name)) {
            return false;
        }

        return (bool) preg_match('/\.zip$/i', $name);
    }

    /**
     * Add directories - recursive
     *
     * @param  array  $directories
     */
    protected function addDirs(array $directories)
    {
        // invariant for the whole method (only depends on the
        // top-level "path" request input, not on $directory/$file) -
        // compute once rather than inside the per-file loop below,
        // where it would otherwise re-resolve and re-validate
        // (prefixer() does a realpath() round trip) on every single
        // file being added to the archive
        $basePathLength = strlen($this->fullPath($this->request->input('path')));

        foreach ($directories as $directory) {

            // Create recursive directory iterator
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($this->prefixer($directory)),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($files as $name => $file) {
                // Get real and relative path for current item
                $filePath = $file->getRealPath();
                $relativePath = substr($filePath, $basePathLength);

                if (!$file->isDir()) {
                    // Add current file to archive
                    $this->zip->addFile($filePath, $relativePath);
                } else {
                    // add empty folders
                    if (!glob($filePath.'/*')) {
                        $this->zip->addEmptyDir($relativePath);
                    }
                }
            }
        }
    }

    /**
     * Create archive name with full path
     *
     * @return string
     */
    protected function createName(): string
    {
        return $this->fullPath($this->request->input('path'))
            .$this->request->input('name');
    }

    /**
     * Generate full path
     *
     * @param $path
     *
     * @return string
     */
    protected function fullPath($path): string
    {
        return $path ? $this->prefixer($path).'/' : $this->prefixer('');
    }
}