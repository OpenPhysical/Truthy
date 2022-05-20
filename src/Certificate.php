<?php
/**
 * This file is part of the Open Physical project.  Copyright (c) 2022, Open Physical Corporation.
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
declare(strict_types=1);

namespace OpenPhysical\Attestation;

use InvalidArgumentException;
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
     * Underlying x509 certificate for this Certificate object
     *
     * @var OpenSSLCertificate
     */
    protected OpenSSLCertificate $certificate;

    /**
     * Subject of the certificate
     *
     * @var string|null
     */
    protected ?string $subject;

    /**
     * Type of the certificate
     *
     * @var int
     */
    protected int $certificateType = IX509Certificate::TYPE_UNKNOWN;

    /**
     * Issuer of the certificate
     *
     * @var IX509Certificate
     */
    protected IX509Certificate $issuer;

    /**
     * Get the type of the certificate
     *
     * @return int
     */
    public function getCertificateType(): int
    {
        return $this->certificateType;
    }

    /**
     * Get the issuer of this Certificate
     *
     * @return IX509Certificate
     */
    public function getIssuer(): IX509Certificate
    {
        return $this->issuer;
    }

    /**
     * Load a certificate from a I/O Stream.
     *
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
            throw new CertificateParsingException(Errors::ERROR_CANT_LOAD_CERT_FROM_STREAM, Errors::ERRNO_CANT_LOAD_CERT_FROM_STREAM);
        }

        return $certificate;
    }

    /**
     * Automatically create a certificate object of the right type for a given certificate and intermediate certificate.
     *
     * @param OpenSSLCertificate $certificate
     * @param OpenSSLCertificate $intermediate
     * @return IX509Certificate
     * @throws CertificateParsingException
     * @throws CertificateValidationException
     */
    public static function Factory(OpenSSLCertificate $certificate, OpenSSLCertificate $intermediate): IX509Certificate
    {
        $parsed = self::parseCertificate($certificate);

        // Determine the certificate type.
        // Look for the YubiKey PIV firmware extension (present in both F9 and 9A-9E certs)
        if (isset($parsed['extensions']) && isset($parsed['extensions'][YubikeyAttestationCertificate::YUBICO_OID_FIRMWARE_VERSION])) {
            return new YubikeyAttestationCertificate($certificate, $intermediate);
        }

        throw new InvalidArgumentException(Errors::ERROR_INVALID_ATTESTATION_CERT, Errors::ERRNO_INVALID_ATTESTATION_CERT);
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
     * Returns the subject of a Certificate.
     *
     * @return string|null
     */
    public function getSubject(): ?string
    {
        return $this->subject;
    }
}
