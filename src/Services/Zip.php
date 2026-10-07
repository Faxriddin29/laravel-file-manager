<?php

namespace Alexusmai\LaravelFileManager\Services;

use Alexusmai\LaravelFileManager\Events\UnzipCreated;
use Alexusmai\LaravelFileManager\Events\UnzipFailed;
use Alexusmai\LaravelFileManager\Events\ZipCreated;
use Alexusmai\LaravelFileManager\Events\ZipFailed;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use RecursiveIteratorIterator;
use RecursiveDirectoryIterator;
use ZipArchive;

class Zip
{
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

    protected function prefixer($path): string
    {
        return Storage::disk($this->request->input('disk'))->path($path);
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

        // Check files for traversal
        if (isset($elements['files']) && is_array($elements['files'])) {
            foreach ($elements['files'] as $file) {
                if (strpos($file, '..') !== false) {
                    event(new ZipFailed($this->request));
                    return false;
                }
            }
        }

        // Check directories for traversal
        if (isset($elements['directories']) && is_array($elements['directories'])) {
            foreach ($elements['directories'] as $directory) {
                if (strpos($directory, '..') !== false) {
                    event(new ZipFailed($this->request));
                    return false;
                }
            }
        }

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
        $zipPath = $this->prefixer($this->request->input('path'));
        $rootPath = dirname($zipPath);

        // extract to new folder
        $folder = $this->request->input('folder');

        if ($folder && !$this->isSafePathSegment($folder, true)) {
            event(new UnzipFailed($this->request));
            return false;
        }

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

        event(new UnzipFailed($this->request));

        return false;
    }

    /**
     * Check that every entry in the currently opened archive would
     * extract to a location inside $destination. Protects against
     * "Zip Slip" - entries using ".." segments or absolute paths to
     * write outside the intended directory.
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
     * for extraction, or - with $allowNestedPaths - a raw zip entry
     * name). Rejects traversal sequences, absolute paths, Windows
     * drive letters, and stream wrappers.
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

        if (str_contains($normalized, '..') || str_contains($normalized, '://')) {
            return false;
        }

        // reject absolute paths (unix) and drive letters (windows)
        if (str_starts_with($normalized, '/') || preg_match('/^[A-Za-z]:/', $normalized)) {
            return false;
        }

        if (!$allowNestedPaths && str_contains($normalized, '/')) {
            return false;
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
     * filename (no directory separators or traversal sequences) with
     * a .zip extension, so it can't be used to write outside the
     * target directory or with a dangerous extension.
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

        if (str_contains($name, '..')) {
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
        foreach ($directories as $directory) {

            // Create recursive directory iterator
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($this->prefixer($directory)),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($files as $name => $file) {
                // Get real and relative path for current item
                $filePath = $file->getRealPath();
                $relativePath = substr(
                    $filePath,
                    strlen($this->fullPath($this->request->input('path')))
                );

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