<?php

/** @noinspection SubStrUsedAsStrPosInspection */

/**
 * This file is part of the Open Physical project.
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
 * Public License as published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
 * details.
 */

namespace OpenPhysical\Attestation;

use OpenPhysical\Attestation\CA\YubicoCaCertificate;
use OpenPhysical\Attestation\Errors;
use OpenPhysical\Attestation\Exception\CertificateParsingException;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;

class Certificate implements IX509Certificate
{
    /**
     * @var \OpenSSLCertificate|string
     */
    protected $certificate;

    protected ?string $subject;

    protected int $certificateType = IX509Certificate::TYPE_UNKNOWN;

    protected IX509Certificate $issuer;

    public function getCertificateType(): int
    {
        return $this->certificateType;
    }

    public function getIssuer(): IX509Certificate
    {
        return $this->issuer;
    }

    /**
     * @return resource|\OpenSSLCertificate
     */
    public static function loadCertificateFromStream($stream)
    {
        if (!$stream) {
            throw new FileNotFoundException(Errors::ERROR_MISSING_CERTIFICATE, Errors::ERRORNO_MISSING_CERTIFICATE);
        }
        $cert_data = stream_get_contents ($stream);
        if (!$cert_data) {
            throw new FileNotFoundException(Errors::ERROR_MISSING_CERTIFICATE, Errors::ERRORNO_MISSING_CERTIFICATE);
        }
        $certificate = openssl_x509_read($cert_data);
        if (false === $certificate) {
            return false;
        }

        return $certificate;
    }

    /**
     * @throws CertificateParsingException
     * @throws \OpenPhysical\PivChecker\Exception\CertificateValidationException
     *
     * @var mixed
     */
    public static function Factory($certificate): IX509Certificate
    {
        $parsed = self::parseCertificate($certificate);

        // Determine the certificate type.
        if (!$parsed) {
            throw new CertificateParsingException(Errors::ERROR_INVALID_CERTIFICATE, Errors::ERRORNO_INVALID_CERTIFICATE);
        }

        // Look for the YubiKey PIV firmware extension (present in both F9 and 9A-9E certs)
        if (isset($parsed['extensions']) && isset ($parsed['extensions'][YubikeyCertificate::YUBICO_OID_FIRMWARE_VERSION])) {
            return new YubikeyCertificate($certificate);
        }

        return new YubicoCaCertificate(IX509Certificate::TYPE_ROOT_CA);
    }

    /**
     * Parse a certificate, storing the certificate subject and issuer for use.
     *
     * @throws CertificateParsingException
     *
     * @var \OpenSSLCertificate|string|array
     */
    public static function parseCertificate($certificate): array
    {
        // If it's already been through openssl_x509_parse, don't run it again.
        if (!is_array($certificate)) {
            $parsed = openssl_x509_parse($certificate);
        } else {
            $parsed = $certificate;
        }

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

    public function getSubject(): ?string
    {
        return $this->subject;
    }
}
