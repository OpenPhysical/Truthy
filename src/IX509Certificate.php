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

/**
 *
 */
interface IX509Certificate
{
    /**
     *
     */
    public const TYPE_UNKNOWN = 0x00;
    /**
     *
     */
    public const TYPE_END_CERTIFICATE = 0x01;
    /**
     *
     */
    public const TYPE_INTERMEDIATE_CA = 0x02;
    /**
     *
     */
    public const TYPE_ROOT_CA = 0x03;

    /**
     * @return int
     */
    public function getCertificateType(): int;

    /**
     * @return string|null
     */
    public function getSubject(): ?string;
}
