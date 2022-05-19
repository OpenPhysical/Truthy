<?php
/**
 * This file is part of the Open Physical project.
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
 * Public License as published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
 * details.
 *
 * PHP Version 8
 * @author Mistial Developer <admin@mistial.dev>
 * @category OpenPhysical
 * @link https://github.com/OpenPhysical/Truthy
 * @license https://www.gnu.org/licenses/agpl-3.0.en.html GNU Affero General Public License, Version 3
 * @package Truthy
 */
namespace Certificate;

use DomainException;
use OpenPhysical\Attestation\Certificate;
use OpenPhysical\Attestation\IX509Certificate;
use OpenPhysical\Attestation\PIV;
use OpenPhysical\Attestation\YubikeyAttestationCertificate;
use OpenPhysical\Attestation\Exception\CertificateParsingException;
use OpenPhysical\Attestation\Exception\CertificateValidationException;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 *
 */
class CertificateTest extends TestCase
{
    /**
     * @var array|false|string
     */
    private array $certificate_files = [];

    /**
     * @return void
     */
    public function setUp(): void
    {
        // Iterate over all the test Certificates
        $directoryIterator = new RecursiveDirectoryIterator(dirname(__DIR__) . DIRECTORY_SEPARATOR);
        /** @var SplFileInfo $file */
        foreach (new RecursiveIteratorIterator($directoryIterator) as $filename => $file) {
            // Only focus on files
            if ($file->isDir() || 'crt' !== $file->getExtension() || str_ends_with($filename, "_f9.crt")) {
                continue;
            }

            $this->certificate_files[] = realpath($filename);
        }
    }

    /**
     * Ensure that the included filenames are valid.
     */
    public function testFilenames(): void
    {
        foreach ($this->certificate_files as $filename) {
            $basename = basename($filename, '.crt');
            if (str_starts_with($basename, 'yk_')) {
                // Yubikey Certificate
                $parts = explode('_', $basename);
                $this->assertCount(4, $parts, 'Invalid certificate filename.');
                $this->assertEquals('yk', $parts[0], 'Invalid certificate filename.');
                $this->assertEquals('attest', $parts[1]);
                $this->assertIsNumeric($parts[2]);

                $key_reference = hexdec($parts[3]);
                $valid_key_references = array_merge(array_keys(YubikeyAttestationCertificate::YUBICO_KEY_REFERENCES), array_keys(PIV::PIV_KEY_REFERENCES));
                $this->assertContains($key_reference, $valid_key_references, 'Invalid certificate filename.');

                // Get the serial number from the filename
                $serialNumber = (int)$parts[2];
                $this->assertGreaterThan(0, $serialNumber, 'Invalid certificate filename.');
            }
        }
    }

    /**
     * @depends testFilenames
     *
     * @throws CertificateParsingException|CertificateValidationException|DomainException
     */
    public function testFactory(): void
    {
        foreach ($this->certificate_files as $filename) {
            $certificate_data = openssl_x509_read(file_get_contents($filename));
            $attestation_cert = openssl_x509_read(file_get_contents(substr($filename, 0, strlen($filename) - 7). '_f9.crt'));
            /** @var YubikeyAttestationCertificate $certificate */
            $certificate = Certificate::Factory($certificate_data, $attestation_cert);
            if (!($certificate instanceof YubikeyAttestationCertificate)) {
                throw new DomainException("Yubikey certificate parsed as non-Yubikey certificate.");
            }

            $basename = basename($filename, '.crt');
            if (str_starts_with($basename, 'yk_')) {
                [$yk_prefix, $attest_text, $serial_number, $keyReference] = explode('_', $basename);
                // F9 key references are intermediate CAs

                // Attestation Certificate
                $this->assertEquals(IX509Certificate::TYPE_END_CERTIFICATE, $certificate->getCertificateType(), 'Non-F9 certificate has wrong certificate type.');

                // Ensure the serial number in the cert matches the filename
                $this->assertEquals((int)$serial_number, $certificate->getSerialNumber());

                // We don't know the exact serial number they changed firmware with, so estimate it.
                if ((int)$serial_number > 15000000) {
                    $expected_firmware = '5.4.2';
                } else {
                    $expected_firmware = '5.2.4';
                }
                $this->assertEquals($expected_firmware, $certificate->getFirmwareVersion(), "Firmware in certificate is not the expected version.");
            }
        }
    }
}
