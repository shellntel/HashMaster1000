"""
Domain extraction and filtering utilities for Hash Master 1000.

This module handles:
- Extracting domain names from pwdump/dcsync usernames (DOMAIN\\user format)
- Extracting domain names from ADD JSON DistinguishedName fields
- Managing domain filter state for report generation
"""

import re
from dataclasses import dataclass, field


# Placeholder domain name for accounts without an explicit domain
NO_DOMAIN = "(No Domain)"


@dataclass
class DomainInfo:
    """Information about domains found in the dataset."""
    domains: dict[str, int] = field(default_factory=dict)  # domain -> account count
    total_accounts: int = 0
    accounts_with_domain: int = 0
    accounts_without_domain: int = 0

    @property
    def domain_count(self) -> int:
        """Number of unique domains found (excluding NO_DOMAIN placeholder)."""
        return len([d for d in self.domains.keys() if d != NO_DOMAIN])

    @property
    def has_multiple_domains(self) -> bool:
        """Check if there are multiple actual domains (not counting NO_DOMAIN)."""
        return self.domain_count > 1

    @property
    def all_domains(self) -> list[str]:
        """Get list of all domains sorted by count (descending), with NO_DOMAIN last."""
        sorted_domains = sorted(
            self.domains.items(),
            key=lambda x: (x[0] == NO_DOMAIN, -x[1])
        )
        return [d[0] for d in sorted_domains]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "domains": self.domains,
            "total_accounts": self.total_accounts,
            "accounts_with_domain": self.accounts_with_domain,
            "accounts_without_domain": self.accounts_without_domain,
            "domain_count": self.domain_count,
            "has_multiple_domains": self.has_multiple_domains,
            "all_domains": self.all_domains
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DomainInfo":
        """Create from dictionary (JSON deserialization)."""
        info = cls()
        info.domains = data.get("domains", {})
        info.total_accounts = data.get("total_accounts", 0)
        info.accounts_with_domain = data.get("accounts_with_domain", 0)
        info.accounts_without_domain = data.get("accounts_without_domain", 0)
        return info


def extract_domain_from_username(username: str) -> tuple[str | None, str]:
    """
    Extract domain name from a username in DOMAIN\\user or DOMAIN/user format.

    Args:
        username: The username string, possibly with domain prefix

    Returns:
        Tuple of (domain, base_username) where domain is None if not found

    Examples:
        "CORP\\jsmith" -> ("CORP", "jsmith")
        "example.com\\jsmith" -> ("example.com", "jsmith")
        "DOMAIN/user" -> ("DOMAIN", "user")
        "jsmith" -> (None, "jsmith")
    """
    if not username:
        return None, ""

    # Check for backslash separator (most common in pwdump/dcsync)
    if '\\' in username:
        parts = username.split('\\', 1)
        if len(parts) == 2 and parts[0]:
            return parts[0].upper(), parts[1]

    # Check for forward slash separator (less common but sometimes seen)
    if '/' in username:
        parts = username.split('/', 1)
        if len(parts) == 2 and parts[0]:
            return parts[0].upper(), parts[1]

    # No domain prefix found
    return None, username


def extract_domain_from_dn(distinguished_name: str) -> str | None:
    """
    Extract domain name from an Active Directory Distinguished Name.

    Args:
        distinguished_name: AD DN like "CN=John Smith,OU=Users,DC=corp,DC=example,DC=com"

    Returns:
        Domain name like "corp.example.com" or None if not found

    Examples:
        "CN=John,OU=Users,DC=corp,DC=example,DC=com" -> "corp.example.com"
        "CN=John,OU=Users" -> None
    """
    if not distinguished_name:
        return None

    # Extract all DC= components
    dc_pattern = re.compile(r'DC=([^,]+)', re.IGNORECASE)
    dc_parts = dc_pattern.findall(distinguished_name)

    if dc_parts:
        return '.'.join(dc_parts).lower()

    return None


def analyze_domains(usernames: list[str]) -> DomainInfo:
    """
    Analyze a list of usernames and extract domain information.

    Args:
        usernames: List of usernames, possibly with domain prefixes

    Returns:
        DomainInfo with domain statistics
    """
    info = DomainInfo()
    info.total_accounts = len(usernames)

    for username in usernames:
        domain, _ = extract_domain_from_username(username)

        if domain:
            info.accounts_with_domain += 1
            info.domains[domain] = info.domains.get(domain, 0) + 1
        else:
            info.accounts_without_domain += 1
            info.domains[NO_DOMAIN] = info.domains.get(NO_DOMAIN, 0) + 1

    return info


def filter_accounts_by_domain(
    account_data: dict[str, dict],
    selected_domain: str | None
) -> dict[str, dict]:
    """
    Filter account data to only include accounts from the selected domain.

    Args:
        account_data: Dictionary of username -> account info
        selected_domain: Domain to filter by, or None/"all" for no filtering

    Returns:
        Filtered account data dictionary
    """
    if not selected_domain or selected_domain.lower() == "all":
        return account_data

    filtered = {}
    for username, data in account_data.items():
        domain, _ = extract_domain_from_username(username)

        # Handle the NO_DOMAIN case
        if selected_domain == NO_DOMAIN:
            if domain is None:
                filtered[username] = data
        elif domain and domain.upper() == selected_domain.upper():
            filtered[username] = data

    return filtered


def get_username_without_domain(username: str) -> str:
    """
    Get the username portion without the domain prefix.

    Args:
        username: Full username possibly with domain

    Returns:
        Username without domain prefix
    """
    _, base_username = extract_domain_from_username(username)
    return base_username


def detect_cross_domain_password_reuse(
    account_data: dict[str, dict],
    domain_info: DomainInfo
) -> list[dict]:
    """
    Detect passwords that are reused across different domains.

    This is a particularly high-risk finding as it means compromising
    a user in one domain could lead to access in another domain.

    Args:
        account_data: Dictionary of username -> account info
        domain_info: Domain information for the dataset

    Returns:
        List of cross-domain password reuse findings
    """
    if not domain_info.has_multiple_domains:
        return []

    # Group accounts by cracked password hash
    password_to_accounts: dict[str, list[tuple[str, str]]] = {}  # ntlm_hash -> [(username, domain), ...]

    for username, data in account_data.items():
        ntlm_hash = data.get("ntlm_hash", "").lower()
        cracked_pw = data.get("cracked_pw")

        # Skip accounts without cracked passwords or blank passwords
        if not cracked_pw or ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
            continue

        domain, base_user = extract_domain_from_username(username)
        domain = domain or NO_DOMAIN

        if ntlm_hash not in password_to_accounts:
            password_to_accounts[ntlm_hash] = []
        password_to_accounts[ntlm_hash].append((username, domain))

    # Find cross-domain reuse
    findings = []
    for ntlm_hash, accounts in password_to_accounts.items():
        if len(accounts) < 2:
            continue

        # Check if accounts span multiple domains
        domains_involved = set(domain for _, domain in accounts)
        if len(domains_involved) > 1:
            # Get the actual password for the report
            sample_username = accounts[0][0]
            password = account_data[sample_username].get("cracked_pw", "")

            findings.append({
                "password": password,
                "ntlm_hash": ntlm_hash,
                "domains": list(domains_involved),
                "accounts": [
                    {"username": username, "domain": domain}
                    for username, domain in accounts
                ],
                "account_count": len(accounts),
                "domain_count": len(domains_involved),
                "risk_level": "CRITICAL" if len(domains_involved) >= 3 else "HIGH"
            })

    # Sort by domain count (most domains first), then by account count
    findings.sort(key=lambda x: (-x["domain_count"], -x["account_count"]))

    return findings
