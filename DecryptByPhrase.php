<?php

use Exception;

trait DecryptByPhrase
{
    public function decrypt($string, $password): ?string
    {
        if (is_null($string) || is_null($password)) {
            return null;
        }

    
        $string = substr($string, 2);   //buang 2 huruf pertama, yaitu 0x


        $data = hex2bin($string);  //ubah ke benytuk binary

        // SQL Server <2017 menggunakan SHA1 untuk key dan DES-EDE-CBC sebagai alogiritma crypto
        // sedangkan SQL Server >= 2017 menggunakan SHA256 dan algoritma AES-256-CBC. 
        // Versi disimpan di 4 byte pertama sebagai integer.
        $version_bytes = substr($data, 0, 4);   
        $version = unpack('V', $version_bytes)[1];  //dapatkan versi sqlserver

        $passwordUtf16 = mb_convert_encoding($password, 'UTF-16LE'); // Password harus di convert ke UTF-16LE encoding

        if ($version === 1) {
            $key = substr(hash('sha1', $passwordUtf16, true), 0, 16);  // Key di hashed menggunakan SHA1, 16 bytes pertama yang digunakan
            $method = 'des-ede-cbc';
            $options = OPENSSL_RAW_DATA;
            $iv = substr($data, 4, 8);
            $encrypted_data = substr($data, 12); //data encrypt yang sebenarnya
        } else if ($version === 2) {
            $key = hash('sha256', $passwordUtf16, true); // Key di hashed menggunakan SHA256, 32 bytes pertama yang digunakan
            $method = 'aes-256-cbc';
            $options = OPENSSL_RAW_DATA;
            $iv = substr($data, 4, 16);
            $encrypted_data = substr($data, 20); //data encrypt yang sebenarnya
        } else {
            throw new \InvalidArgumentException('Invalid version');  //jika versi tidak ditemukan
        }

        $decrypted = openssl_decrypt($encrypted_data, $method, $key, $options, $iv);

        if ($decrypted === false) {
            return null; //jika decrypt gagal
        }
        $decrypted = substr($decrypted, 8);

        return $decrypted;
    }
}
