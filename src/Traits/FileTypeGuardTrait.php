<?php

namespace Alexusmai\LaravelFileManager\Traits;

trait FileTypeGuardTrait
{
    /**
     * Extensions that are never allowed to be written to a managed
     * disk, regardless of the configured "allowFileTypes" list. This
     * list is intentionally hard-coded - a permissive allowFileTypes
     * configuration must not be able to re-enable remote code
     * execution by accidentally (or maliciously) including one of
     * these.
     */
    protected const DANGEROUS_EXTENSIONS = [
        'php', 'php1', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
        'phps', 'pht', 'phtm', 'phtml', 'phar',
        'cgi', 'fcgi', 'pl', 'py', 'rb',
        'sh', 'bash', 'ksh', 'csh', 'ps1',
        'asp', 'aspx', 'ashx', 'asmx', 'cer', 'asa', 'asax',
        'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
        'exe', 'dll', 'bat', 'cmd', 'com', 'scr', 'msi',
        'vbs', 'vbe', 'wsf', 'wsh', 'jar',
    ];

    /**
     * Exact filenames (case-insensitive, matched on the full
     * basename) that are never allowed, regardless of extension -
     * mainly server config files that can change how other files in
     * the same directory are handled (e.g. enabling PHP execution for
     * other extensions, or auto-prepending a malicious file).
     */
    protected const DANGEROUS_FILENAMES = [
        '.htaccess', '.htpasswd', '.user.ini', 'web.config', 'php.ini',
    ];

    /**
     * Signatures that reliably indicate embedded, executable script
     * content - used to catch payloads smuggled inside a file with an
     * otherwise-innocuous extension (e.g. a ".png" containing PHP
     * code, later renamed to ".php").
     */
    protected const EXECUTABLE_SIGNATURES = [
        '<?php', '<?=', '<%', '<script language="php"', "<script language='php'",
    ];

    /**
     * @param  string|null  $extension
     *
     * @return bool
     */
    protected function hasDangerousExtension(?string $extension): bool
    {
        if (!$extension) {
            return false;
        }

        return in_array(strtolower($extension), self::DANGEROUS_EXTENSIONS, true);
    }

    /**
     * @param  string|null  $filename
     *
     * @return bool
     */
    protected function hasDangerousFilename(?string $filename): bool
    {
        if (!$filename) {
            return false;
        }

        return in_array(strtolower($filename), self::DANGEROUS_FILENAMES, true);
    }

    /**
     * Is this extension acceptable to write to a managed disk?
     * The hard-coded dangerous-extension list always applies; the
     * configured allowlist (if any) is enforced on top of it. An
     * empty allowlist means "no additional restriction" - matching
     * the package's existing "allowFileTypes: [] = no restrictions"
     * semantics - but the dangerous-extension denylist still applies.
     *
     * @param  string|null  $extension
     * @param  array        $allowList
     *
     * @return bool
     */
    protected function isAllowedExtension(?string $extension, array $allowList): bool
    {
        if ($this->hasDangerousExtension($extension)) {
            return false;
        }

        if (empty($allowList)) {
            return true;
        }

        if (!$extension) {
            return false;
        }

        return in_array(
            strtolower($extension),
            array_map('strtolower', $allowList),
            true
        );
    }

    /**
     * Scan a file's content for signatures that indicate embedded,
     * executable script content, regardless of its claimed extension.
     * Scanning is capped at 5MB for performance - files larger than
     * that still go through the extension/filename checks above, but
     * are not content-scanned.
     *
     * @param  string|null  $absolutePath
     *
     * @return bool
     */
    protected function containsExecutableSignature(?string $absolutePath): bool
    {
        if (!$absolutePath || !is_readable($absolutePath)) {
            return false;
        }

        $handle = @fopen($absolutePath, 'rb');
        if (!$handle) {
            return false;
        }

        $maxBytes = 5 * 1024 * 1024;
        $read     = 0;
        $tail     = '';

        while (!feof($handle) && $read < $maxBytes) {
            $chunk = fread($handle, 8192);
            if ($chunk === false) {
                break;
            }

            $read += strlen($chunk);
            $haystack = strtolower($tail.$chunk);

            foreach (self::EXECUTABLE_SIGNATURES as $needle) {
                if (str_contains($haystack, strtolower($needle))) {
                    fclose($handle);

                    return true;
                }
            }

            // keep a small overlap so a signature straddling a chunk
            // boundary isn't missed
            $tail = substr($chunk, -10);
        }

        fclose($handle);

        return false;
    }
}
