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

namespace OpenPhysical\Attestation\CA;

use OpenPhysical\Attestation\Certificate;
use OpenPhysical\Attestation\IX509Certificate;
use OpenPhysical\Attestation\Errors;
use OpenSSLCertificate;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;

/**
 *
 */
class CaCertificate extends Certificate implements ICaCertificate
{
    /**
     * @var string|null
     */
    public ?string $subject;

    /**
     * @var int
     */
    protected int $certificateType = IX509Certificate::TYPE_ROOT_CA;

    /**
     * @var OpenSSLCertificate
     */
    protected OpenSSLCertificate $certificate;

    /**
     * @return string|null
     */
    public function getSubject(): ?string
    {
        return $this->subject;
    }

    /**
     * @param string $name
     * @return bool
     */
    public static function handlesSubject(string $name): bool
    {
        return false;
    }

    /**
     * @return int
     */
    public function getCertificateType(): int
    {
        return $this->certificateType;
    }

    /**
     * @return OpenSSLCertificate
     */
    public function getCertificate(): OpenSSLCertificate
    {
        return $this->certificate;
    }

    /**
     * @param OpenSSLCertificate $certificate
     */
    public function setCertificate(OpenSSLCertificate $certificate): void
    {
        $this->certificate = $certificate;
    }
}
