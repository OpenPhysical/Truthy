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

use InvalidArgumentException;
use OpenPhysical\Attestation\Exception\CertificateParsingException;
use OpenPhysical\PivChecker\Errors;
use OpenPhysical\PivChecker\Exception\CertificateValidationException;

class YubikeyCertificate extends PivCertificate implements IX509Certificate
{
    public const YUBICO_OID_PIV_ROOT = '1.3.6.1.4.1.41482.3';
    public const YUBICO_OID_FIRMWARE_VERSION = '1.3.6.1.4.1.41482.3.3';
    public const YUBICO_OID_SERIAL_NUMBER = '1.3.6.1.4.1.41482.3.7';
    public const YUBICO_OID_PIN_TOUCH_POLICY = '1.3.6.1.4.1.41482.3.8';
    public const YUBICO_OID_FORM_FACTOR = '1.3.6.1.4.1.41482.3.9';
    public const YUBICO_OID_FIPS_VALIDATED = '1.3.6.1.4.1.41482.3.10';

    public const YUBICO_PIN_POLICY_NEVER = 0x01;
    public const YUBICO_PIN_POLICY_ONCE_PER_SESSION = 0x02;
    public const YUBICO_PIN_POLICY_ALWAYS = 0x03;

    public const YUBICO_TOUCH_POLICY_NEVER = 0x01;
    public const YUBICO_TOUCH_POLICY_ALWAYS = 0x02;
    public const YUBICO_TOUCH_POLICY_CACHE_15s = 0x03;

    public const YUBICO_FORM_FACTOR_UNDEFINED = 0x00;
    public const YUBICO_FORM_FACTOR_USB_A_KEYCHAIN = 0x01;
    public const YUBICO_FORM_FACTOR_USB_A_NANO = 0x02;
    public const YUBICO_FORM_FACTOR_USB_C_KEYCHAIN = 0x03;
    public const YUBICO_FORM_FACTOR_USB_C_NANO = 0x04;
    public const YUBICO_FORM_FACTOR_USB_C_LIGHTNING = 0x05;

    public const VALID_SLOTS = ['9a', '9c', '9d', '9e', 'f9'];

    /**
     * @var \OpenSSLCertificate|string
     */
    protected $certificate;

    protected ?string $firmware_version = null;
    protected ?int $serial_number = null;
    protected ?int $pin_policy = null;
    protected ?int $touch_policy = null;
    protected ?int $form_factor = null;

    /**
     * @param $certificate \OpenSSLCertificate|string Input certificate
     *
     * @throws CertificateValidationException
     */
    public function __construct($certificate)
    {
        $parsed = openssl_x509_parse($certificate);
        if (!($parsed) || !isset($parsed['extensions'])) {
            throw new CertificateValidationException(Errors::ERROR_CERTIFICATE_MISSING_EXTENSIONS, Errors::ERRORNO_CERTIFICATE_MISSING_EXTENSIONS);
        }

        // Require at least one Yubikey Extension to succeed
        $extensions = $parsed['extensions'];
        $found_yubikey_extension = false;
        foreach ($extensions as $key => $value) {
            if (0 === strpos($key, self::YUBICO_OID_PIV_ROOT)) {
                $found_yubikey_extension = true;
                break;
            }
        }

        // If it has no Yubikey extensions, it's fundamentally not a YubiKey certificate.
        if (!$found_yubikey_extension) {
            throw new CertificateValidationException(Errors::ERROR_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS, Errors::ERRORNO_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS);
        }

        // Handle the firmware version extension
        if (isset($extensions[self::YUBICO_OID_FIRMWARE_VERSION])) {
            $firmware_version = $extensions[self::YUBICO_OID_FIRMWARE_VERSION];
            $bytes = str_split($firmware_version);

            // Convert the binary encoding to decimal encoding
            array_walk($bytes, static function (&$value, $key) {
                $value = ord($value);
            });

            $this->firmware_version = implode('.', $bytes);
        }

        // Convert the serial number from binary encoding
        if (isset($extensions[self::YUBICO_OID_SERIAL_NUMBER])) {
            $binary_serial = $extensions[self::YUBICO_OID_SERIAL_NUMBER];

            // Split the serial number into its individual bytes.
            $bytes = str_split($binary_serial);
            /* @noinspection TypeUnsafeComparisonInspection */
            if (empty($bytes) || (0x02 != ord($bytes[0])) || (ord($bytes[1]) != count($bytes) - 2)) {
                throw new InvalidArgumentException(Errors::ERROR_INVALID_CERTIFICATE, Errors::ERRORNO_INVALID_CERTIFICATE);
            }

            // Calculate the serial number using the raw bytes.
            $serial_number = 0;
            $byte_count = ord($bytes[1]);
            for ($i = 0; $i < $byte_count; ++$i) {
                $serial_number = ($serial_number * 256) + ord($bytes[2 + $i]);
            }

            $this->serial_number = $serial_number;
        }

        // Pin and touch policy
        if (isset($extensions[self::YUBICO_OID_PIN_TOUCH_POLICY])) {
            $bytes = str_split($extensions[self::YUBICO_OID_PIN_TOUCH_POLICY]);
            /* @noinspection TypeUnsafeComparisonInspection */
            if (empty($bytes) || 2 != count($bytes)) {
                throw new InvalidArgumentException(Errors::ERROR_INVALID_CERTIFICATE, Errors::ERRORNO_INVALID_CERTIFICATE);
            }

            $this->pin_policy = ord($bytes[0]);
            $this->touch_policy = ord($bytes[1]);
        }

        // Form Factor
        if (isset($extensions[self::YUBICO_OID_FORM_FACTOR])) {
            // ASN.1 tag, primitive, context-specific.  May have 0x80 set, which needs to be removed if present
            $byte = ord($extensions[self::YUBICO_OID_FORM_FACTOR]);
            $this->form_factor = $byte & (~0x80);
        }

        // FIPS status
        if (isset($extensions[self::YUBICO_OID_FIPS_VALIDATED])) {
            $this->isFipsValidated = true;
        }

        // Slot
        if (isset($parsed['subject'], $parsed['subject']['CN'])) {
            $cn_words = explode(' ', $parsed['subject']['CN']);
            $word_count = count($cn_words);

            // We are looking for a slot number as the last word
            if ($word_count > 1 && 2 === strlen($cn_words[$word_count - 1]) && 'Attestation' === $cn_words[$word_count - 2]) {
                $this->slot = $cn_words[$word_count - 1];
                $this->certificateType = IX509Certificate::TYPE_END_CERTIFICATE;
            } else {
                // F9 slots don't have a slot in the CN
                if ('Yubico PIV Attestation' === $parsed['subject']['CN']) {
                    $this->certificateType = IX509Certificate::TYPE_INTERMEDIATE_CA;
                    $this->slot = 'f9';
                } else {
                    throw new CertificateParsingException(Errors::ERROR_CERTIFICATE_UNKNOWN_TYPE, Errors::ERRORNO_CERTIFICATE_UNKNOWN_TYPE);
                }
            }
        }
    }

    public function __toString(): string
    {
        $ret = 'YubiKey Attestation Cert';

        if (isset($this->slot)) {
            $ret .= ' for slot '.$this->slot;
        }

        if (false === $this->isFipsValidated) {
            $ret .= ' from a non-FIPS YubiKey';
        } else {
            $ret .= ' from a FIPS-validated YubiKey';
        }

        // Form factor
        if (isset($this->form_factor)) {
            // USB Type
            if (self::YUBICO_FORM_FACTOR_USB_A_KEYCHAIN === $this->form_factor || self::YUBICO_FORM_FACTOR_USB_A_NANO === $this->form_factor) {
                $ret .= ' USB Type A';
            } elseif (self::YUBICO_FORM_FACTOR_USB_C_KEYCHAIN === $this->form_factor || self::YUBICO_FORM_FACTOR_USB_C_NANO === $this->form_factor || self::YUBICO_FORM_FACTOR_USB_C_LIGHTNING === $this->form_factor) {
                $ret .= ' USB Type C';
            }

            // Form factor
            if (self::YUBICO_FORM_FACTOR_USB_A_KEYCHAIN === $this->form_factor || self::YUBICO_FORM_FACTOR_USB_C_KEYCHAIN === $this->form_factor) {
                $ret .= ' Keychain';
            } elseif (self::YUBICO_FORM_FACTOR_USB_A_NANO === $this->form_factor || self::YUBICO_FORM_FACTOR_USB_C_NANO === $this->form_factor) {
                $ret .= ' Nano';
            } elseif (self::YUBICO_FORM_FACTOR_USB_C_LIGHTNING === $this->form_factor) {
                $ret .= ' and Lightning';
            }

            if (self::YUBICO_FORM_FACTOR_UNDEFINED === $this->form_factor) {
                $ret .= ' of unknown form factor';
            }
        }

        // Serial Number
        if (isset($this->serial_number)) {
            $ret .= sprintf(', Serial Number %d', $this->serial_number);
        }

        // Firmware Version
        if (isset($this->firmware_version)) {
            $ret .= sprintf(', Firmware version %s', $this->firmware_version);
        }

        // Pin policy
        if (isset($this->pin_policy)) {
            $ret .= ', PIN Policy: ';
            switch ($this->pin_policy) {
                case self::YUBICO_PIN_POLICY_NEVER:
                    $ret .= 'never required';
                    break;
                case self::YUBICO_PIN_POLICY_ONCE_PER_SESSION:
                    $ret .= 'required once per session';
                    break;
                case self::YUBICO_PIN_POLICY_ALWAYS:
                    $ret .= 'always required';
                    break;
                default:
                    $ret .= 'unknown or invalid';
                    break;
            }
        }

        // Touch policy
        if (isset($this->touch_policy)) {
            $ret .= ', Touch Policy: ';
            switch ($this->touch_policy) {
                case self::YUBICO_TOUCH_POLICY_NEVER:
                    $ret .= 'never required';
                    break;
                case self::YUBICO_TOUCH_POLICY_ALWAYS:
                    $ret .= 'always required';
                    break;
                case self::YUBICO_TOUCH_POLICY_CACHE_15s:
                    $ret .= 'cached for 15 seconds after touch';
                    break;
                default:
                    $ret .= 'unknown or invalid';
            }
        }

        return $ret;
    }


    public function getFirmwareVersion(): ?string
    {
        return $this->firmware_version;
    }

    public function getSerialNumber(): ?int
    {
        return $this->serial_number;
    }

    /**
     * @return \OpenSSLCertificate|string
     */
    public function getCertificate()
    {
        return $this->certificate;
    }
}
