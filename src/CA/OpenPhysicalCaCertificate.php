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

class OpenPhysicalCaCertificate extends CaCertificate implements ICaCertificate
{
    public static function handlesSubject(string $name): bool
    {
        // TODO: Implement handlesSubject() method.
        return false;
    }
}
