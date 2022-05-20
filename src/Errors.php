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
class Errors
{
    /**
     * The YubiKey CA ID specified is invalid.
     */
    public const ERRORNO_INVALID_ID = 0x11;

    /**
     * The YubiKey CA name specified is invalid.
     */
    public const ERRORNO_INVALID_NAME = 0x12;

    /**
     * The certificate supplied is invalid.
     */
    public const ERRORNO_INVALID_CERTIFICATE = 0x21;

    /**
     * The certificate supplied is missing the required extensions.
     */
    public const ERRORNO_CERTIFICATE_MISSING_EXTENSIONS = 0x22;

    /**
     * The certificate supplied is missing any YubiKey extensions.
     */
    public const ERRORNO_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS = 0x23;

    /**
     * The certificate supplied is missing a subject.
     */
    public const ERRORNO_CERTIFICATE_MISSING_SUBJECT = 0x24;

    /**
     * The specified certificate could not be found.
     */
    public const ERRORNO_MISSING_CERTIFICATE = 0x33;

    /**
     * The certificate has an unknown type.
     */
    public const ERRORNO_CERTIFICATE_UNKNOWN_TYPE = 0x40;

    /**
     * Yubikey certificate parsed as non-Yubikey certificate.
     */
    public const ERRNO_CERTIFICATE_NOT_YUBIKEY = 0x41;

    /**
     * Invalid attestation certificate provided.
     */
    public const ERRNO_INVALID_ATTESTATION_CERT = 0x42;

    /**
     * Unable to load certificate form stream.
     */
    public const ERRNO_CANT_LOAD_CERT_FROM_STREAM = 0x50;

    /**
     * Thrown when a YubiKey CA identifier is provided, but no such CA exists.
     */
    public const ERROR_INVALID_ID = 'The YubiKey CA ID specified is invalid.';

    /**
     * Thrown when a YubiKey CA is identified by name, but no such CA exists.
     */
    public const ERROR_INVALID_NAME = 'The YubiKey CA name specified is invalid.';

    /**
     * Thrown when an input is not a valid x509 certificate.
     */
    public const ERROR_INVALID_CERTIFICATE = 'The certificate supplied is invalid.';

    /**
     * Thrown when a provided certificate needs specific extensions, and those extensions are not present.
     */
    public const ERROR_CERTIFICATE_MISSING_EXTENSIONS = 'The certificate supplied is missing the required extensions.';

    /**
     * Thrown when a provided certificate is well-constructed, but it is being loaded as a YubiKey certificate and is lacking the appropriate extensions for such.
     */
    public const ERROR_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS = 'The certificate supplied is missing any YubiKey extensions.';

    /**
     * Thrown when the certificate doesn't have a subject to identify who it applies to.
     */
    public const ERROR_CERTIFICATE_MISSING_SUBJECT = 'The certificate supplied is missing a subject.';

    /**
     * Thrown when a certificate file is specified, but the file does not exist or have a certificate in it.
     */
    public const ERROR_MISSING_CERTIFICATE = 'The specified certificate could not be found.';

    /**
     * Thrown when a x509 certificate is of an unknown type.
     */
    public const ERROR_CERTIFICATE_UNKNOWN_TYPE = 'The certificate has an unknown type.';

    /**
     * Thrown when a certificate is not supposed to have YubiKey extensions, yet it does anyway.
     */
    public const ERROR_CERTIFICATE_NOT_YUBIKEY = 'Yubikey certificate parsed as non-Yubikey certificate.';

    /**
     * Thrown when an attestation certificate is invalid.
     */
    public const ERROR_INVALID_ATTESTATION_CERT = 'Invalid attestation certificate provided.';

    /**
     * Thrown when attempts to load a certificate from a stream (such as a file stream) fail.
     */
    public const ERROR_CANT_LOAD_CERT_FROM_STREAM = 'Unable to load certificate form stream.';
}
