# OpenPhysical Truthy

This library is under heavy development and should not be used in production.

Security Tokens (like the Yubico Yubikey) have the capability to generate keys
internally, protecting them against unauthorized export or duplication.

Additionally, these tokens may contain an "attestation key", which allows the
software to sign an assertion that the key was generated on-device, as well as
provide specifics of the security status of the device.  For example, YubiKey
attestation certificates include the firmware version, PIN, and touch policy
used for the slot/key reference.

This library provides an interface to automatically validate and parse these
attestation certificates.
