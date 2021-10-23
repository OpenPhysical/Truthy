<?php

require_once '../../../vendor/autoload.php';

$directory = new DirectoryIterator(__DIR__);
$iterator = new RegexIterator($directory, '/\.crt$/i', RegexIterator::MATCH);
foreach ($iterator as $fileinfo) {
    if ($fileinfo->isDot()) {
        continue;
    }

    $cert_data = file_get_contents($fileinfo->getRealPath());
    $cert = openssl_x509_read($cert_data);

    $ykcert = new \OpenPhysical\Attestation\YubikeyCertificate($cert);
    echo sprintf("File %s:\n  %s\n\n", $fileinfo, $ykcert);
}
