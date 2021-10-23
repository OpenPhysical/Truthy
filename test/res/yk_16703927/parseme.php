<?php

    $cert = file_get_contents('yk_attest_16703927_f9.crt');
        $certificate = openssl_x509_read($cert);
        $parsed = openssl_x509_parse($certificate);
    $parts = [];
    if (isset($parsed['subject'])) {
        $names = $parsed['subject'];
        foreach ($names as $key=>$value) {
            $parts[] = $key . ' = ' . $value;
        }
    }
    $subject = implode(', ', $parts);
    var_dump($subject);
