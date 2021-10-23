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
 */
declare(strict_types=1);

namespace OpenPhysical\Attestation\CA;

use OpenPhysical\Attestation\Certificate;
use OpenPhysical\Attestation\IX509Certificate;
use OpenPhysical\Attestation\Errors;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;

class CaCertificate extends Certificate implements ICaCertificate
{
    public ?string $subject;

    protected int $certificateType = IX509Certificate::TYPE_ROOT_CA;

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    public static function handlesSubject(string $name): bool
    {
        return false;
    }

    public function getCertificateType(): int
    {
        return $this->certificateType;
    }
}
