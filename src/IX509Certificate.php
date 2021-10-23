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

namespace OpenPhysical\Attestation;

interface IX509Certificate
{
    public const TYPE_UNKNOWN = 0x00;
    public const TYPE_END_CERTIFICATE = 0x01;
    public const TYPE_INTERMEDIATE_CA = 0x02;
    public const TYPE_ROOT_CA = 0x03;

    public function getCertificateType(): int;

    public function getSubject(): ?string;
}
