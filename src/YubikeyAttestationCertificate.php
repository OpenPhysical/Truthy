<?php
/**
 * This file is part of the Open Physical project.  Copyright 2022, Open Physical Corporation.
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

use DomainException;
use InvalidArgumentException;
use OpenPhysical\Attestation\CA\YubicoCaCertificate;
use OpenPhysical\Attestation\Exception\CertificateParsingException;
use OpenPhysical\Attestation\Exception\CertificateValidationException;
use OpenSSLCertificate;

class YubikeyAttestationCertificate extends PivAttestationCertificate implements IX509Certificate
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

    public const YUBICO_KEY_REFERENCES = [0xF9 => 'Attestation Key'];

    public const OPENSSL_VERIFY_SUCCESS = 1;
    public const OPENSSL_VERIFY_FAILURE = 0;
    public const OPENSSL_VERIFY_ERROR = -1;

    /**
     * OpenSSL certificate representing the loaded attestation certificate.
     * @var OpenSSLCertificate
     */
    protected OpenSSLCertificate $certificate;

    protected ?string $firmware_version = null;
    protected ?int $serial_number = null;
    protected ?int $pin_policy = null;
    protected ?int $touch_policy = null;
    protected ?int $form_factor = null;

    /**
     * Parse a YubiKey attestation certificate, extracting YubiKey extensions.
     * @param $certificate OpenSSLCertificate   Attestation certificate to verify.
     * @param OpenSSLCertificate $intermediate_certificate   Intermediate (F9) certificate for chain verification.
     * @throws CertificateParsingException
     * @throws CertificateValidationException
     * @noinspection PhpMissingParentConstructorInspection
     */
    public function __construct(OpenSSLCertificate $certificate, OpenSSLCertificate $intermediate_certificate)
    {
        $parsed_cert = openssl_x509_parse($certificate);
        if (!($parsed_cert) || !isset($parsed_cert['extensions'])) {
            throw new CertificateValidationException(Errors::ERROR_CERTIFICATE_MISSING_EXTENSIONS, Errors::ERRORNO_CERTIFICATE_MISSING_EXTENSIONS);
        }

        $parsed_intermediate = openssl_x509_parse($intermediate_certificate);
        if (!($parsed_intermediate) || !isset($parsed_intermediate['extensions'])) {
            throw new CertificateValidationException(Errors::ERROR_CERTIFICATE_MISSING_EXTENSIONS, Errors::ERRORNO_CERTIFICATE_MISSING_EXTENSIONS);
        }

        // Require at least one Yubikey Extension to succeed
        $extensions = $parsed_cert['extensions'];
        $found_yubikey_extension = false;
        foreach ($extensions as $key => $value) {
            if (str_starts_with($key, self::YUBICO_OID_PIV_ROOT)) {
                $found_yubikey_extension = true;
                break;
            }
        }

        // If it has no Yubikey extensions, it's fundamentally not a YubiKey certificate.
        if (!$found_yubikey_extension) {
            throw new CertificateValidationException(Errors::ERROR_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS, Errors::ERRORNO_CERTIFICATE_MISSING_YUBIKEY_EXTENSIONS);
        }

        // Verify the certificate chain
        $issuer_name = $parsed_cert['issuer']['CN'];
        $intermediate_subject = $parsed_intermediate['subject']['CN'];
        if ($issuer_name != $intermediate_subject) {
            throw new InvalidArgumentException("Intermediate certificate did not issue this attestation certificate.");
        }
        $root_name = 'CN = ' . $parsed_intermediate['issuer']['CN'];
        $root_certificate = YubicoCaCertificate::LoadByName($root_name)->getCertificate();

        // Verify the intermediate chains to the root, and that the signature is valid on the certificate.
        if (self::OPENSSL_VERIFY_SUCCESS != openssl_x509_verify($intermediate_certificate, $root_certificate)) {
            throw new CertificateValidationException("Intermediate CA was not generated properly by the root CA it should be.");
        } elseif (self::OPENSSL_VERIFY_SUCCESS != openssl_x509_verify($certificate, $intermediate_certificate)) {
            throw new CertificateValidationException("Attestation certificate was not signed properly by the intermediate CA.");
        }

        // Handle the firmware version extension
        if (isset($extensions[self::YUBICO_OID_FIRMWARE_VERSION])) {
            $firmware_version = $extensions[self::YUBICO_OID_FIRMWARE_VERSION];
            $bytes = str_split($firmware_version);

            // Convert the binary encoding to decimal encoding
            array_walk($bytes, static function (&$value) {
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

        // Key Reference
        if (isset($parsed_cert['subject'], $parsed_cert['subject']['CN'])) {
            $cn_words = explode(' ', $parsed_cert['subject']['CN']);
            $word_count = count($cn_words);

            // We are looking for a slot number as the last word
            if ($word_count > 1 && 2 === strlen($cn_words[$word_count - 1]) && 'Attestation' === $cn_words[$word_count - 2]) {
                $key_reference = hexdec($cn_words[$word_count - 1]);
                if (!isset(PIV::PIV_KEY_REFERENCES[$key_reference])) {
                    throw new DomainException("Invalid key reference specified.");
                }
                $this->keyReference = $key_reference;
                $this->certificateType = IX509Certificate::TYPE_END_CERTIFICATE;
            } else {
                // F9 slots don't have a slot in the CN
                if ('Yubico PIV Attestation' === $parsed_cert['subject']['CN']) {
                    $this->certificateType = IX509Certificate::TYPE_INTERMEDIATE_CA;
                    $this->keyReference = 0xF9;
                } else {
                    throw new CertificateParsingException(Errors::ERROR_CERTIFICATE_UNKNOWN_TYPE, Errors::ERRORNO_CERTIFICATE_UNKNOWN_TYPE);
                }
            }
        }
    }

    public function __toString(): string
    {
        $ret = 'YubiKey Attestation Cert';

        if (isset($this->keyReference)) {
            $ret .= ' for slot '.$this->keyReference;
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
            $ret .= match ($this->pin_policy) {
                self::YUBICO_PIN_POLICY_NEVER => 'never required',
                self::YUBICO_PIN_POLICY_ONCE_PER_SESSION => 'required once per session',
                self::YUBICO_PIN_POLICY_ALWAYS => 'always required',
                default => 'unknown or invalid',
            };
        }

        // Touch policy
        if (isset($this->touch_policy)) {
            $ret .= ', Touch Policy: ';
            $ret .= match ($this->touch_policy) {
                self::YUBICO_TOUCH_POLICY_NEVER => 'never required',
                self::YUBICO_TOUCH_POLICY_ALWAYS => 'always required',
                self::YUBICO_TOUCH_POLICY_CACHE_15s => 'cached for 15 seconds after touch',
                default => 'unknown or invalid',
            };
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
     * @return OpenSSLCertificate
     */
    public function getCertificate(): OpenSSLCertificate
    {
        return $this->certificate;
    }
}
