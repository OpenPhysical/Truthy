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

use InvalidArgumentException;
use OpenPhysical\Attestation\Errors;
use OpenPhysical\Attestation\Exception\CertificateParsingException;

/**
 *
 */
class YubicoCaCertificate extends CaCertificate implements ICaCertificate
{
    /**
     * Version 2 of the YubiKey hardware attestation CA
     */
    public const YUBIKEY_CA_V2 = 0x01;
    /**
     * Preview version of the YubiKey hardware attestation CA
     */
    public const YUBIKEY_CA_PIV_PREVIEW = 0x02;
    /**
     * U2F YubiKey attestation CA
     */
    public const YUBIKEY_CA_U2F = 0x03;

    /**
     * @var int
     */
    protected int $type;

    /**
     * Maps IDs to certificate subjects.
     * @var array|string[] Subject of the token CA
     */
    protected static array $yubikey_ca = [
        self::YUBIKEY_CA_V2 => 'CN = Yubico PIV Root CA Serial 263751',
        self::YUBIKEY_CA_U2F => 'CN = Yubico U2F Root CA Serial 457200631',
        self::YUBIKEY_CA_PIV_PREVIEW => 'CN = Yubico PIV Preview CA',
    ];

    /**
     * Maps IDs to filenames.
     * @var array|string[] filename for the attestation certificate (PEM format)
     */
    protected static array $yubikey_sca_certfiles = [
        self::YUBIKEY_CA_V2 => 'res/yubikey-attest-v2.pem',
        self::YUBIKEY_CA_U2F => 'res/yubikey-u2f.pem',
        self::YUBIKEY_CA_PIV_PREVIEW => 'res/yubikey-piv-preview.pem',
    ];

    /**
     * Returns true if the class can handle a token CA subject.
     */
    public static function handlesSubject(string $name): bool
    {
        $id = in_array($name, self::$yubikey_ca, true);
        return !(false === $id);
    }

    /**
     * Load a Yubikey CA by certificate subject.
     * @throws CertificateParsingException
     */
    public static function LoadByName(string $name): ICaCertificate
    {
        $id = array_search($name, self::$yubikey_ca, true);
        var_dump($name);
        if (false === $id) {
            throw new InvalidArgumentException(Errors::ERROR_INVALID_NAME, Errors::ERRORNO_INVALID_NAME);
        }

        return new YubicoCaCertificate($id);
    }

    /**
     * Instantiate a new YubiKey CA by ID.
     * @throws CertificateParsingException
     */
    public function __construct(int $id)
    {
        if ($id < self::YUBIKEY_CA_V2 || $id > self::YUBIKEY_CA_U2F) {
            throw new InvalidArgumentException(Errors::ERROR_INVALID_ID, Errors::ERRORNO_INVALID_ID);
        }

        $this->type = $id;

        $ca_file = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . self::$yubikey_sca_certfiles[$id];
        $fp = fopen($ca_file, 'r');
        $this->certificate = $this->loadCertificateFromStream($fp);
    }

    /**
     * Get the common name associated with this YubiKey CA.
     */
    public function getSubject(): string
    {
        return self::$yubikey_ca[$this->type];
    }
}
