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
namespace OpenPhysical\Attestation;

use OpenPhysical\Attestation\CA\YubicoCaCertificate;
use OpenPhysical\Attestation\Errors;
use OpenPhysical\Attestation\Exception\CertificateParsingException;
use OpenPhysical\Attestation\Exception\CertificateValidationException;
use OpenSSLCertificate;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;

/**
 *
 */
class Certificate implements IX509Certificate
{
    /**
     * @var OpenSSLCertificate
     */
    protected OpenSSLCertificate $certificate;

    /**
     * @var string|null
     */
    protected ?string $subject;

    /**
     * @var int
     */
    protected int $certificateType = IX509Certificate::TYPE_UNKNOWN;

    /**
     * @var IX509Certificate
     */
    protected IX509Certificate $issuer;

    /**
     * @return int
     */
    public function getCertificateType(): int
    {
        return $this->certificateType;
    }

    /**
     * @return IX509Certificate
     */
    public function getIssuer(): IX509Certificate
    {
        return $this->issuer;
    }

    /**
     * @param $stream
     * @return OpenSSLCertificate
     * @throws CertificateParsingException
     */
    public static function loadCertificateFromStream($stream): OpenSSLCertificate
    {
        if (!$stream) {
            throw new FileNotFoundException(Errors::ERROR_MISSING_CERTIFICATE, Errors::ERRORNO_MISSING_CERTIFICATE);
        }
        $cert_data = stream_get_contents($stream);
        if (!$cert_data) {
            throw new FileNotFoundException(Errors::ERROR_MISSING_CERTIFICATE, Errors::ERRORNO_MISSING_CERTIFICATE);
        }
        $certificate = openssl_x509_read($cert_data);
        if (false === $certificate) {
            throw new CertificateParsingException("Unable to load certificate form stream.");
        }

        return $certificate;
    }

    /**
     * @return IX509Certificate
     * @throws CertificateParsingException
     * @throws Exception\CertificateValidationException
     * @var mixed
     */
    public static function Factory(OpenSSLCertificate $certificate, OpenSSLCertificate $intermediate): IX509Certificate
    {
        $parsed = self::parseCertificate($certificate);

        // Determine the certificate type.
        // Look for the YubiKey PIV firmware extension (present in both F9 and 9A-9E certs)
        if (isset($parsed['extensions']) && isset($parsed['extensions'][YubikeyAttestationCertificate::YUBICO_OID_FIRMWARE_VERSION])) {
            return new YubikeyAttestationCertificate($certificate, $intermediate);
        }

        throw new \InvalidArgumentException("Invalid attestation certificate provided.");
    }

    /**
     * Parse a certificate, storing the certificate subject and issuer for use.
     *
     * @return array
     * @throws CertificateParsingException
     * @var OpenSSLCertificate
     */
    public static function parseCertificate(OpenSSLCertificate $certificate): array
    {
        $parsed = openssl_x509_parse($certificate);

        // Ensure a valid certificate was specified
        if (false === $parsed) {
            throw new CertificateParsingException(Errors::ERROR_INVALID_CERTIFICATE, Errors::ERRORNO_INVALID_CERTIFICATE);
        }

        // Attempt to build the subject
        $parts = [];
        if (!isset($parsed['subject'])) {
            throw new CertificateParsingException(Errors::ERROR_CERTIFICATE_MISSING_SUBJECT, Errors::ERRORNO_CERTIFICATE_MISSING_SUBJECT);
        }
        $names = $parsed['subject'];
        foreach ($names as $key => $value) {
            $parts[] = $key.' = '.$value;
        }

        $ret = [];
        $ret['subject'] = implode(', ', $parts);

        // Include the extensions, if present
        if (isset($parsed['extensions'])) {
            $ret['extensions'] = $parsed['extensions'];
        }

        return $ret;
    }

    /**
     * @return string|null
     */
    public function getSubject(): ?string
    {
        return $this->subject;
    }
}
