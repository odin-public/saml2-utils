<?php

// Fake
class SimpleSAML_Utilities {
    public static function generateID() {
        return '_' . self::stringToHex(self::generateRandomBytes(21));
    }

    /**
     * This function generates a binary string containing random bytes.
     *
     * It will use /dev/urandom if available, and fall back to the builtin mt_rand()-function if not.
     *
     * @param $length  The number of random bytes to return.
     * @return A string of lenght $length with random bytes.
     */
    public static function generateRandomBytes($length, $fallback = TRUE) {
            static $fp = NULL;
            assert('is_int($length)');

            if($fp === NULL) {
                    if (file_exists('/dev/urandom')) {
                            $fp = fopen('/dev/urandom', 'rb');
                    } else {
                            $fp = FALSE;
                    }
            }

            if($fp !== FALSE) {
                    /* Read random bytes from /dev/urandom. */
                    $data = fread($fp, $length);
                    if($data === FALSE) {
                            throw new Exception('Error reading random data.');
                    }
                    if(strlen($data) != $length) {
                            SimpleSAML_Logger::warning('Did not get requested number of bytes from random source. Requested (' . $length . ') got (' . strlen($data) . ')');
                            if ($fallback) {
                                    $data = self::generateRandomBytesMTrand($length);
                            } else {
                                    throw new Exception('Did not get requested number of bytes from random source. Requested (' . $length . ') got (' . strlen($data) . ')');
                            }
                    }
            } else {
                    /* Use mt_rand to generate $length random bytes. */
                    $data = self::generateRandomBytesMTrand($length);
            }

            return $data;
    }

    /**
     * This function converts a binary string to hexadecimal characters.
     *
     * @param $bytes  Input string.
     * @return String with lowercase hexadecimal characters.
     */
    public static function stringToHex($bytes) {
            $ret = '';
            for($i = 0; $i < strlen($bytes); $i++) {
                    $ret .= sprintf('%02x', ord($bytes[$i]));
            }
            return $ret;
    }

    public static function addURLparameter($dist, $params) {}
    public static function resolveCert($args) {}
    public static function loadPrivateKey($arg) {}
    public static function loadPublicKey($arg) {}
    public static function getTempDir() {}
    public static function writeFile($file, $data) {}
    public static function debugMessage($msg, $t) {}
    public static function redirectTrustedURL($url, $data) {}
    public static function postRedirect($url, $data) {}
}

?>
