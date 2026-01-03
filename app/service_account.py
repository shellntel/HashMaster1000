"""
Service Account Identification Module

Provides functions to identify and analyze service accounts from Active Directory data.
Service accounts are identified by the presence of ServicePrincipalNames (SPNs).

Key capabilities:
- Identify service accounts based on SPN presence
- Parse UserAccountControl (UAC) flags from RawUACValue
- Parse supportedEncryptionTypes bitmask
- Identify delegation configurations (unconstrained, constrained, RBCD)
- Determine account privilege level via adminCount
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
from typing import Any


class UserAccountControlFlags(IntFlag):
    """
    Windows UserAccountControl bit flags.
    Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
    """
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000  # Unconstrained delegation
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000  # AS-REP roastable
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # Constrained delegation with protocol transition
    PARTIAL_SECRETS_ACCOUNT = 0x04000000


class EncryptionTypes(IntFlag):
    """
    Kerberos supported encryption types bitmask.
    Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
    """
    DES_CBC_CRC = 0x01
    DES_CBC_MD5 = 0x02
    RC4_HMAC = 0x04  # Vulnerable to Kerberoasting
    AES128_CTS_HMAC_SHA1 = 0x08
    AES256_CTS_HMAC_SHA1 = 0x10


@dataclass
class DelegationInfo:
    """Delegation configuration for an account."""
    unconstrained: bool = False  # TRUSTED_FOR_DELEGATION flag
    constrained: bool = False  # Has allowedToDelegateTo entries
    constrained_with_protocol_transition: bool = False  # TRUSTED_TO_AUTH_FOR_DELEGATION flag
    delegation_targets: list[str] = field(default_factory=list)  # SPNs this account can delegate to

    @property
    def has_delegation(self) -> bool:
        """Check if any delegation is configured."""
        return self.unconstrained or self.constrained


@dataclass
class ServiceAccountInfo:
    """
    Detailed information about a service account.
    """
    sam_account_name: str
    distinguished_name: str = ""
    description: str = ""

    # SPN information
    spns: list[str] = field(default_factory=list)
    is_service_account: bool = False  # True if has SPNs

    # Account status
    enabled: bool = True
    is_privileged: bool = False  # adminCount == 1

    # UAC analysis
    raw_uac_value: int = 0
    uac_flags: set[str] = field(default_factory=set)
    password_never_expires: bool = False
    preauth_not_required: bool = False  # AS-REP roastable

    # Encryption types
    supported_encryption_types: int = 0
    supports_rc4: bool = True  # Default - vulnerable to Kerberoasting
    supports_aes: bool = False
    supports_des: bool = False
    encryption_type_names: list[str] = field(default_factory=list)

    # Delegation
    delegation: DelegationInfo = field(default_factory=DelegationInfo)

    # Password info (to be populated from password analysis)
    pwd_last_set: str = ""
    last_logon: str = ""


def parse_uac_flags(raw_uac_value: str | int) -> tuple[int, set[str]]:
    """
    Parse UserAccountControl value into integer and set of flag names.

    Args:
        raw_uac_value: UAC value as string or integer

    Returns:
        Tuple of (integer value, set of flag names)
    """
    if isinstance(raw_uac_value, str):
        try:
            uac_int = int(raw_uac_value) if raw_uac_value else 0
        except ValueError:
            uac_int = 0
    else:
        uac_int = raw_uac_value

    flags: set[str] = set()

    for flag in UserAccountControlFlags:
        if uac_int & flag:
            flags.add(flag.name)

    return uac_int, flags


def parse_encryption_types(supported_enc_types: str | int) -> tuple[int, list[str], bool, bool, bool]:
    """
    Parse supportedEncryptionTypes value.

    When this attribute is not set or is 0, Windows defaults to RC4 for backward compatibility.

    Args:
        supported_enc_types: Encryption types value as string or integer

    Returns:
        Tuple of (integer value, list of type names, supports_rc4, supports_aes, supports_des)
    """
    if isinstance(supported_enc_types, str):
        try:
            enc_int = int(supported_enc_types) if supported_enc_types else 0
        except ValueError:
            enc_int = 0
    else:
        enc_int = supported_enc_types

    type_names: list[str] = []
    supports_rc4 = False
    supports_aes = False
    supports_des = False

    if enc_int == 0:
        # Default behavior - RC4 is supported
        supports_rc4 = True
        type_names.append("RC4_HMAC (default)")
    else:
        if enc_int & EncryptionTypes.DES_CBC_CRC:
            type_names.append("DES_CBC_CRC")
            supports_des = True
        if enc_int & EncryptionTypes.DES_CBC_MD5:
            type_names.append("DES_CBC_MD5")
            supports_des = True
        if enc_int & EncryptionTypes.RC4_HMAC:
            type_names.append("RC4_HMAC")
            supports_rc4 = True
        if enc_int & EncryptionTypes.AES128_CTS_HMAC_SHA1:
            type_names.append("AES128")
            supports_aes = True
        if enc_int & EncryptionTypes.AES256_CTS_HMAC_SHA1:
            type_names.append("AES256")
            supports_aes = True

        # If only AES is set, RC4 might still be used as fallback in some configs
        # but we report what's explicitly configured
        if not type_names:
            # No known bits set - unusual configuration
            type_names.append(f"Unknown ({enc_int})")
            supports_rc4 = True  # Assume vulnerable

    return enc_int, type_names, supports_rc4, supports_aes, supports_des


def parse_delegation_info(
    uac_int: int,
    uac_flags: set[str],
    allowed_to_delegate_to: list[str]
) -> DelegationInfo:
    """
    Parse delegation configuration from UAC flags and allowedToDelegateTo.

    Args:
        uac_int: Integer UAC value
        uac_flags: Set of UAC flag names
        allowed_to_delegate_to: List of SPNs this account can delegate to

    Returns:
        DelegationInfo with delegation configuration
    """
    delegation = DelegationInfo()

    # Unconstrained delegation
    if "TRUSTED_FOR_DELEGATION" in uac_flags:
        delegation.unconstrained = True

    # Constrained delegation
    if allowed_to_delegate_to:
        delegation.constrained = True
        delegation.delegation_targets = list(allowed_to_delegate_to)

    # Protocol transition (S4U2Self)
    if "TRUSTED_TO_AUTH_FOR_DELEGATION" in uac_flags:
        delegation.constrained_with_protocol_transition = True

    return delegation


def identify_service_account(user_data: dict[str, Any]) -> ServiceAccountInfo:
    """
    Analyze a user object and return service account information.

    Args:
        user_data: Dictionary containing user attributes from ADD JSON export.
            Expected keys:
            - SamAccountName (required)
            - ServicePrincipalNames (array)
            - RawUACValue (string)
            - UserAccountControl (array of flag names)
            - adminCount (string "0" or "1")
            - supportedEncryptionTypes (string)
            - allowedToDelegateTo (array)
            - DistinguishedName (string)
            - Description (string)
            - PwdLastSet (string)
            - LastLogon (string)

    Returns:
        ServiceAccountInfo with analyzed account details
    """
    sam_account_name = user_data.get("SamAccountName", "")

    info = ServiceAccountInfo(
        sam_account_name=sam_account_name,
        distinguished_name=user_data.get("DistinguishedName", ""),
        description=user_data.get("Description", ""),
    )

    # SPNs - presence indicates service account
    spns = user_data.get("ServicePrincipalNames", [])
    if spns is None:
        spns = []
    info.spns = list(spns)
    info.is_service_account = len(spns) > 0

    # Parse UAC
    raw_uac = user_data.get("RawUACValue", "0")
    info.raw_uac_value, info.uac_flags = parse_uac_flags(raw_uac)

    # Check specific UAC flags
    info.enabled = "ACCOUNTDISABLE" not in info.uac_flags
    info.password_never_expires = "DONT_EXPIRE_PASSWORD" in info.uac_flags
    info.preauth_not_required = "DONT_REQ_PREAUTH" in info.uac_flags

    # adminCount - indicates protected/privileged account
    admin_count = user_data.get("adminCount", "0")
    info.is_privileged = admin_count == "1"

    # Encryption types
    enc_types = user_data.get("supportedEncryptionTypes", "")
    (
        info.supported_encryption_types,
        info.encryption_type_names,
        info.supports_rc4,
        info.supports_aes,
        info.supports_des
    ) = parse_encryption_types(enc_types)

    # Delegation
    allowed_to_delegate = user_data.get("allowedToDelegateTo", [])
    if allowed_to_delegate is None:
        allowed_to_delegate = []
    info.delegation = parse_delegation_info(
        info.raw_uac_value,
        info.uac_flags,
        allowed_to_delegate
    )

    # Password timestamps
    info.pwd_last_set = user_data.get("PwdLastSet", "")
    info.last_logon = user_data.get("LastLogon", "")

    return info


def get_service_accounts(users: list[dict[str, Any]]) -> list[ServiceAccountInfo]:
    """
    Filter and return only service accounts from a list of users.

    Args:
        users: List of user dictionaries from ADD JSON export

    Returns:
        List of ServiceAccountInfo for accounts with SPNs
    """
    service_accounts = []

    for user in users:
        info = identify_service_account(user)
        if info.is_service_account:
            service_accounts.append(info)

    return service_accounts


def get_kerberoastable_accounts(users: list[dict[str, Any]], include_disabled: bool = False) -> list[ServiceAccountInfo]:
    """
    Return accounts that can be Kerberoasted.

    Kerberoastable accounts:
    - Have at least one SPN
    - Are user accounts (not computer accounts)
    - Are enabled (unless include_disabled=True)

    Args:
        users: List of user dictionaries from ADD JSON export
        include_disabled: Whether to include disabled accounts

    Returns:
        List of ServiceAccountInfo for Kerberoastable accounts
    """
    kerberoastable = []

    for user in users:
        info = identify_service_account(user)

        # Must have SPNs
        if not info.is_service_account:
            continue

        # Check if enabled
        if not include_disabled and not info.enabled:
            continue

        # Exclude computer accounts (they have SPNs but aren't typically targeted)
        # Computer accounts have SamAccountName ending in $
        if info.sam_account_name.endswith("$"):
            continue

        # Exclude krbtgt - special account, not useful to crack
        if info.sam_account_name.lower() == "krbtgt":
            continue

        kerberoastable.append(info)

    return kerberoastable


def get_asrep_roastable_accounts(users: list[dict[str, Any]], include_disabled: bool = False) -> list[ServiceAccountInfo]:
    """
    Return accounts vulnerable to AS-REP roasting.

    AS-REP roastable accounts:
    - Have DONT_REQ_PREAUTH flag set
    - Are enabled (unless include_disabled=True)

    Args:
        users: List of user dictionaries from ADD JSON export
        include_disabled: Whether to include disabled accounts

    Returns:
        List of ServiceAccountInfo for AS-REP roastable accounts
    """
    asrep_roastable = []

    for user in users:
        info = identify_service_account(user)

        # Must have preauth not required
        if not info.preauth_not_required:
            continue

        # Check if enabled
        if not include_disabled and not info.enabled:
            continue

        asrep_roastable.append(info)

    return asrep_roastable


def get_delegation_accounts(users: list[dict[str, Any]]) -> dict[str, list[ServiceAccountInfo]]:
    """
    Return accounts with delegation configured, grouped by type.

    Args:
        users: List of user dictionaries from ADD JSON export

    Returns:
        Dict with keys: 'unconstrained', 'constrained', 'protocol_transition'
    """
    result = {
        "unconstrained": [],
        "constrained": [],
        "protocol_transition": [],
    }

    for user in users:
        info = identify_service_account(user)

        if info.delegation.unconstrained:
            result["unconstrained"].append(info)

        if info.delegation.constrained:
            result["constrained"].append(info)

        if info.delegation.constrained_with_protocol_transition:
            result["protocol_transition"].append(info)

    return result
