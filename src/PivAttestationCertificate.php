<?php
/**
 * This file is part of the Open Physical project.  Copyright 2022, Open Physical Corporation.
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
 * Public License as published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
 * details.
 */
declare(strict_types=1);

namespace OpenPhysical\Attestation;

use OpenSSLCertificate;

/**
 * Represents an attestation certificate, which cryptographically demonstrates that a key was likely generated on a cryptographic token.
 */
class PivAttestationCertificate extends Certificate implements IX509Certificate
{

    /**
     * Key reference that this certificate applies to.  See SP 800-73-4, Part 1, Table 4b.
     * @var int Key Reference (e.g. 0x9A)
     */
    protected int $keyReference;

    /**
     * Indicates that the attestation certificate is for a key located on a FIPS Validated token.
     * @var bool
     */
    protected bool $isFipsValidated = false;

    /**
     * OpenSSL Certificate object containing the loaded attestation certificate.
     * @var OpenSSLCertificate attestation certificate
     */
    protected $certificate;

    /**
     * @return OpenSSLCertificate
     */
    public function getCertificate(): OpenSSLCertificate
    {
        return $this->certificate;
    }

    /**
     * Retrieves the key reference associated with the given certificate.
     * @return int
     */
    public function getKeyReference(): int
    {
        return $this->keyReference;
    }

    /**
     * @param $certificate OpenSSLCertificate Attestation Certificate
     * @param $keyReference int Key Reference (see SP 800-73-4, Part 1, Table 4b.)
     * @param $isFipsValidated bool Indicates if the PIV token is FIPS validated.
     */
    public function __construct(OpenSSLCertificate $certificate, int $keyReference, bool $isFipsValidated = false)
    {
        if (!isset(PIV::PIV_KEY_REFERENCES[$keyReference])) {
            throw new \InvalidArgumentException("Invalid key reference specified.");
        }
        $this->certificate = $certificate;
        $this->keyReference = $keyReference;
        $this->isFipsValidated = $isFipsValidated;
    }

    /**
     * Retrieves the FIPS validation status for the token that generated the key in the attestation certificate.
     * @return bool
     */
    public function getIsFipsValidated(): bool
    {
        return $this->isFipsValidated;
    }
}
