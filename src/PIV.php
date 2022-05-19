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
class PIV
{
    /**
     *
     */
    public const PIV_AUTHENTICATION_DATA_REFERENCES = [
        0x00 => 'Global PIN',
        0x80 => 'PIV Card Application PIN',
        0x81 => 'PIN Unblocking Key',
        0x96 => 'Primary Finger OCC',
        0x97 => 'Secondary Finger OCC',
        0x98 => 'Pairing Code',
    ];

    /**
     *
     */
    public const PIV_KEY_REFERENCES = [
        0x04 => 'PIV Secure Messaging Key',
        0x9A => 'PIV Authentication Key',
        0x9B => 'PIV Card Application Administration Key',
        0x9C => 'Digital Signature Key',
        0x9D => 'Key Management Key',
        0x9E => 'Card Authentication Key',
        0x82 => 'Retired Key Management Key 1',
        0x83 => 'Retired Key Management Key 2',
        0x84 => 'Retired Key Management Key 3',
        0x85 => 'Retired Key Management Key 4',
        0x86 => 'Retired Key Management Key 5',
        0x87 => 'Retired Key Management Key 6',
        0x88 => 'Retired Key Management Key 7',
        0x89 => 'Retired Key Management Key 8',
        0x8A => 'Retired Key Management Key 9',
        0x8B => 'Retired Key Management Key 10',
        0x8C => 'Retired Key Management Key 11',
        0x8D => 'Retired Key Management Key 12',
        0x8E => 'Retired Key Management Key 13',
        0x8F => 'Retired Key Management Key 14',
        0x90 => 'Retired Key Management Key 15',
        0x91 => 'Retired Key Management Key 16',
        0x92 => 'Retired Key Management Key 17',
        0x93 => 'Retired Key Management Key 18',
        0x94 => 'Retired Key Management Key 19',
        0x95 => 'Retired Key Management Key 20',
    ];
}
