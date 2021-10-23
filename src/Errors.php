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

namespace OpenPhysical\PivChecker;

class Errors
{
    public const ERRORNO_CANT_RUN = 0x01;
    public const ERRORNO_INVALID_ID = 0x11;
    public const ERRORNO_INVALID_NAME = 0x12;
    public const ERRORNO_INVALID_CERTIFICATE = 0x21;
    public const ERRORNO_CERTIFICATE_MISSING_EXTENSIONS = 0x22;
    public const ERRORNO_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS = 0x23;
    public const ERRORNO_CERTIFICATE_MISSING_SUBJECT = 0x24;
    public const ERRORNO_MISSING_CERTIFICATE = 0x33;
    public const ERRORNO_CERTIFICATE_UNKNOWN_TYPE = 0x40;

    public const ERROR_CANT_RUN = 'Unable to run application.';
    public const ERROR_INVALID_ID = 'The YubiKey CA ID specified is invalid.';
    public const ERROR_INVALID_NAME = 'The YubiKey CA name specified is invalid.';
    public const ERROR_INVALID_CERTIFICATE = 'The certificate supplied is invalid.';
    public const ERROR_CERTIFICATE_MISSING_EXTENSIONS = 'The certificate supplied is missing the required extensions.';
    public const ERROR_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS = 'The certificate supplied is missing any YubiKey extensions.';
    public const ERROR_CERTIFICATE_MISSING_SUBJECT = 'The certificate supplied is missing a subject';
    public const ERROR_MISSING_CERTIFICATE = 'The specified certificate could not be found.';
    public const ERROR_CERTIFICATE_UNKNOWN_TYPE = 'The certificate has an unknown type.';
}
