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

/**
 *
 */
class OpenPhysicalCaCertificate extends CaCertificate implements ICaCertificate
{
    /**
     * @param string $name
     * @return bool
     */
    public static function handlesSubject(string $name): bool
    {
        // TODO: Implement handlesSubject() method.
        return false;
    }
}
