<?php
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped, WordPress.WP.AlternativeFunctions -- Bundled third-party library (MaxMind DB Reader, Apache-2.0), code unchanged: Tegatai catches every exception and never outputs a message unescaped, and the local database is read with PHP stream functions (seek/read on an open handle, not possible with WP_Filesystem)

declare(strict_types=1);

namespace MaxMind\Db\Reader;

class Util
{
    /**
     * @param resource    $stream
     * @param int<0, max> $numberOfBytes
     */
    public static function read($stream, int $offset, int $numberOfBytes): string
    {
        if ($numberOfBytes === 0) {
            return '';
        }
        if (fseek($stream, $offset) === 0) {
            $value = fread($stream, $numberOfBytes);

            // We check that the number of bytes read is equal to the number
            // asked for. We use ftell as getting the length of $value is
            // much slower.
            if ($value !== false && ftell($stream) - $offset === $numberOfBytes) {
                return $value;
            }
        }

        throw new InvalidDatabaseException(
            'The MaxMind DB file contains bad data'
        );
    }
}
