<?php

/** @noinspection SubStrUsedAsStrPosInspection */

namespace OpenPhysical\Attestation\Test\Certificate;

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

class CertificateTest extends TestCase
{
    private array $certificate_files = [];

    public function setUp(): void
    {
        // Iterate over all the test Certificates
        $directoryIterator = new RecursiveDirectoryIterator(dirname(__DIR__) . DIRECTORY_SEPARATOR);
        /** @var SplFileInfo $file */
        foreach (new RecursiveIteratorIterator($directoryIterator) as $filename => $file) {
            // Only focus on files
            if ($file->isDir() || 'crt' !== $file->getExtension()) {
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
                $serialNumber = $parts[2];
                $this->assertGreaterThan(0, $serialNumber, 'Invalid certificate filename.');
            }
        }
    }

    /**
     * @depends testFilenames
     *
     * @throws CertificateParsingException|CertificateValidationException
     * @noinspection SubStrUsedAsStrPosInspection
     */
    public function testFactory(): void
    {
        foreach ($this->certificate_files as $filename) {
            $contents = file_get_contents($filename);
            $parsed = openssl_x509_read($contents);
            $certificate = Certificate::Factory($parsed);

            $basename = basename($filename, '.crt');
            if ('yk_' === substr($basename, 0, 3)) {
                [$yk_prefix, $attest_text, $serial_number, $slot] = explode('_', $basename);
                // F9 slots are intermediate CAs
                if ('f9' === $slot) {
                    $this->assertEquals(IX509Certificate::TYPE_INTERMEDIATE_CA, $certificate->getCertificateType(), 'F9 certificate has wrong certificate type.');
                } else {
                    $this->assertEquals(IX509Certificate::TYPE_END_CERTIFICATE, $certificate->getCertificateType(), 'Non-F9 certificate has wrong certificate type.');
                }
            }
        }
    }
}
