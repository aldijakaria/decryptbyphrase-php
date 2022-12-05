<?php

use Exception;

trait DecryptByPhrase
{
    public function decrypt($string, $password = null): ?string
    {
        if (is_null($string)) {
            return null;
        }

        $string = substr($string, 2);

        $data = hex2bin($string);
        $version_bytes = substr($data, 0, 4);
        $version = unpack('V', $version_bytes)[1];
        $passwordUtf16 = mb_convert_encoding($password, 'UTF-16LE');

        if ($version === 1) {
            $key = substr(hash('sha1', $passwordUtf16, true), 0, 16);
            $method = 'des-ede-cbc';
            $options = OPENSSL_RAW_DATA;
            $iv = substr($data, 4, 8);
            $encrypted_data = substr($data, 12);
        } else if ($version === 2) {
            $key = hash('sha256', $passwordUtf16, true);
            $method = 'aes-256-cbc';
            $options = OPENSSL_RAW_DATA;
            $iv = substr($data, 4, 16);
            $encrypted_data = substr($data, 20);
        } else {
            throw new \InvalidArgumentException('Invalid version');
        }

        $decrypted = openssl_decrypt($encrypted_data, $method, $key, $options, $iv);

        if ($decrypted === false) {
            return null;
        }
        $decrypted = substr($decrypted, 8);

        return $decrypted;
    }
}
