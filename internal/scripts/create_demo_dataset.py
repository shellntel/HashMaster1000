#!/usr/bin/env python3
"""
Create Demo Dataset for Hash Master 1000

Creates a comprehensive ~1000 account ADD JSON dataset with matching potfile
that exercises all report features:
- Various password lengths (to test min length policy)
- Various complexity levels (to test complexity policy)
- Password reuse patterns
- Bad practices (seasons, company names, keyboard patterns, etc.)
- Privileged accounts (Domain Admins, etc.)
- Various account states (enabled, disabled, expired)
- LM hashes for legacy testing
- Blank passwords
- Kerberoast-related fields (SPNs, delegation, encryption types, adminCount)

Usage:
    python scripts/create_demo_dataset.py
"""

import hashlib
import json
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

# Configuration
NUM_ACCOUNTS = 1000
COMPANY_NAME = "DemoCorp"
DOMAIN = "democorp.local"
CRACK_RATE_TARGET = 0.35  # 35% crack rate

# Service Principal Name templates for realistic SPN generation
SPN_TEMPLATES = [
    "HTTP/{hostname}.{domain}",
    "HTTP/{hostname}",
    "MSSQLSvc/{hostname}.{domain}:1433",
    "MSSQLSvc/{hostname}.{domain}",
    "LDAP/{hostname}.{domain}/{domain}",
    "exchangeMDB/{hostname}.{domain}",
    "exchangeRFR/{hostname}.{domain}",
    "SMTP/{hostname}.{domain}",
    "FTP/{hostname}.{domain}",
    "WSMAN/{hostname}.{domain}",
    "RestrictedKrbHost/{hostname}.{domain}",
    "HOST/{hostname}.{domain}",
    "cifs/{hostname}.{domain}",
    "TERMSRV/{hostname}.{domain}",
]

# Service account naming patterns with associated SPNs
SERVICE_ACCOUNT_CONFIGS = {
    "svc_sql": {
        "spns": ["MSSQLSvc/sqlserver.{domain}:1433", "MSSQLSvc/sqlserver.{domain}"],
        "description": "SQL Server Service Account",
        "delegation_targets": [],
        "enc_types": "24",  # AES128 + AES256
        "privileged": False,
    },
    "svc_web": {
        "spns": ["HTTP/webserver.{domain}", "HTTP/www.{domain}"],
        "description": "IIS Web Server Service Account",
        "delegation_targets": ["LDAP/DC01.{domain}/{domain}", "MSSQLSvc/sqlserver.{domain}:1433"],
        "enc_types": "24",
        "privileged": False,
    },
    "svc_exchange": {
        "spns": ["exchangeMDB/exchange.{domain}", "exchangeRFR/exchange.{domain}", "SMTP/exchange.{domain}"],
        "description": "Exchange Service Account",
        "delegation_targets": [],
        "enc_types": "24",
        "privileged": True,  # Exchange accounts often have high privileges
    },
    "svc_backup": {
        "spns": ["HOST/backup.{domain}"],
        "description": "Backup Service Account",
        "delegation_targets": [],
        "enc_types": "4",  # RC4 only - legacy/vulnerable
        "privileged": True,  # Backup operators have high privileges
    },
    "svc_print": {
        "spns": ["printserver/printsvr.{domain}"],
        "description": "Print Spooler Service Account",
        "delegation_targets": [],
        "enc_types": "0",  # Default (RC4)
        "privileged": False,
    },
    "svc_ftp": {
        "spns": ["FTP/ftpserver.{domain}"],
        "description": "FTP Service Account",
        "delegation_targets": [],
        "enc_types": "4",  # RC4 - legacy
        "privileged": False,
    },
    "svc_monitor": {
        "spns": ["WSMAN/monitor.{domain}"],
        "description": "Monitoring Service Account",
        "delegation_targets": [],
        "enc_types": "24",
        "privileged": False,
    },
    "svc_deploy": {
        "spns": ["HOST/deploy.{domain}", "WSMAN/deploy.{domain}"],
        "description": "Deployment Service Account",
        "delegation_targets": [],
        "enc_types": "24",
        "privileged": True,
    },
    "svc_ldap": {
        "spns": ["LDAP/ldapproxy.{domain}/{domain}"],
        "description": "LDAP Proxy Service Account",
        "delegation_targets": ["LDAP/DC01.{domain}/{domain}"],
        "enc_types": "24",
        "privileged": False,
    },
    "svc_scheduler": {
        "spns": ["HOST/scheduler.{domain}"],
        "description": "Task Scheduler Service Account",
        "delegation_targets": [],
        "enc_types": "0",  # Default
        "privileged": False,
    },
}

# Departments for realistic user distribution
DEPARTMENTS = {
    "IT": {"count": 80, "admin_ratio": 0.3},
    "Finance": {"count": 100, "admin_ratio": 0.05},
    "HR": {"count": 60, "admin_ratio": 0.02},
    "Sales": {"count": 200, "admin_ratio": 0.01},
    "Marketing": {"count": 80, "admin_ratio": 0.01},
    "Engineering": {"count": 150, "admin_ratio": 0.1},
    "Operations": {"count": 100, "admin_ratio": 0.02},
    "Legal": {"count": 40, "admin_ratio": 0.02},
    "Executive": {"count": 30, "admin_ratio": 0.5},
    "Support": {"count": 100, "admin_ratio": 0.05},
    "Research": {"count": 60, "admin_ratio": 0.08},
}

# First names and last names for generating realistic usernames
FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kevin", "Dorothy", "Brian", "Carol", "George", "Amanda", "Edward", "Melissa",
    "Ronald", "Deborah", "Timothy", "Stephanie", "Jason", "Rebecca", "Jeffrey", "Sharon",
    "Ryan", "Laura", "Jacob", "Cynthia", "Gary", "Kathleen", "Nicholas", "Amy",
    "Eric", "Angela", "Jonathan", "Shirley", "Stephen", "Anna", "Larry", "Brenda",
    "Justin", "Pamela", "Scott", "Emma", "Brandon", "Nicole", "Benjamin", "Helen",
    "Samuel", "Samantha", "Raymond", "Katherine", "Gregory", "Christine", "Frank", "Debra",
    "Alexander", "Rachel", "Patrick", "Carolyn", "Henry", "Janet", "Jack", "Catherine",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
]

# Password patterns for bad practices testing
BAD_PRACTICE_PASSWORDS = {
    "season_year": [
        "Summer2024!", "Winter2024#", "Fall2024$", "Spring2024@",
        "Summer2023!", "Winter2023#", "Fall2023$", "Spring2023@",
        "Summer2025!", "Winter2025#", "Fall2025$", "Spring2025@",
    ],
    "company_related": [
        "DemoCorp2024!", "DemoCorp123", "Demo2024!", "Corp2024#",
        "DemoCorpIT!", "DemoCorp@123", "democorp!", "DEMOCORP1",
    ],
    "keyboard_patterns": [
        "Qwerty123!", "Qwerty2024", "Asdfgh123!", "Zxcvbn123!",
        "1qaz2wsx!", "Qazwsx123", "123qwe!@#", "!QAZ2wsx",
    ],
    "common_words": [
        "Password1!", "Welcome123!", "Letmein123", "Admin123!",
        "Changeme1!", "Temp1234!", "Test1234!", "Default123!",
    ],
    "sequential_numbers": [
        "User12345!", "Account123!", "Pass123456", "Login12345!",
        "Number123!", "Abc123456!", "123456789a", "987654321!",
    ],
    "repeated_characters": [
        "Aaaa1111!", "Bbbb2222@", "Cccc3333#", "Dddd4444$",
        "Passss123!", "Userrrr1!", "Adminnn1!", "Testtttt1",
    ],
    "dictionary_words": [
        "Sunshine123!", "Football2024", "Baseball123!", "Dragon2024!",
        "Monkey12345", "Shadow2024!", "Master1234!", "Michael123!",
    ],
    "date_patterns": [
        "Jan2024!!", "Dec2024!!", "01012024!", "12252024!",
        "Birthday1!", "2024Jan01!", "Christmas1", "NewYear24!",
    ],
    "sports_teams": [
        "Patriots123!", "Cowboys2024", "Lakers2024!", "Yankees123!",
        "Packers2024", "Bears12345!", "Chiefs2024!", "Eagles123!",
    ],
    "pop_culture": [
        "Starwars123!", "Marvel2024!", "Batman2024!", "Superman1!",
        "Pokemon2024", "Disney123!!", "Netflix123!", "Spotify24!",
    ],
}

# Strong passwords (won't be cracked)
STRONG_PASSWORDS = [
    "X#9kL$mN2pQr@vW!", "7Yz*Bc&dEf8Gh!jK", "Mn3$Pq@rSt5Uv#Wx",
    "4Ab*Cd2Ef&Gh8Ij!", "Kl5@Mn#Op7Qr$St!", "Uv9&Wx*Yz2Ab3Cd!",
]

# Short passwords (fail min length)
SHORT_PASSWORDS = [
    "Pass1!", "Ab12!", "Test!", "Hi123", "Go2024", "Me123!",
    "No1234", "Yes12!", "Ok123!", "Up2024",
]

# Simple passwords (fail complexity)
SIMPLE_PASSWORDS = [
    "password", "12345678", "abcdefgh", "qwertyui",
    "letmein1", "welcome1", "changeme", "adminadmin",
]


def generate_ntlm_hash(password: str) -> str:
    """Generate NTLM hash for a password using passlib or fallback."""
    try:
        # Try using passlib if available
        from passlib.hash import nthash
        return nthash.hash(password)
    except ImportError:
        pass

    try:
        # Try native hashlib (may not work on all systems)
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    except ValueError:
        pass

    # Fallback: generate a deterministic fake hash based on password
    # This allows consistent hashes for the same password
    hash_input = f"ntlm:{password}".encode()
    return hashlib.sha256(hash_input).hexdigest()[:32]


def generate_lm_hash() -> str:
    """Generate a fake LM hash (for testing LM hash detection)."""
    return ''.join(random.choices('0123456789abcdef', k=32))


# Global potfile cache
_POTFILE_CACHE: Dict[str, str] = {}  # password -> hash

# Passwords to exclude from demo data (e.g., real client passwords that shouldn't appear in demos)
EXCLUDED_PASSWORDS = {
    "Brookfield53005$",
    "Doctor Manhattan!!",
    "Everyonelovesracing2",
    "Greenbaypackers0202!!",
    "SCtemp123!@#",
}


def load_potfile_hashes(potfile_path: str) -> Dict[str, str]:
    """Load hash:password pairs from a potfile and return password->hash mapping."""
    global _POTFILE_CACHE
    if _POTFILE_CACHE:
        return _POTFILE_CACHE

    try:
        with open(potfile_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ntlm_hash, password = parts
                        if len(ntlm_hash) == 32 and password not in EXCLUDED_PASSWORDS:
                            _POTFILE_CACHE[password] = ntlm_hash.lower()
    except FileNotFoundError:
        pass

    return _POTFILE_CACHE


def get_hash_for_password(password: str, potfile_path: str = None) -> str:
    """Get or generate NTLM hash for a password."""
    if potfile_path:
        cache = load_potfile_hashes(potfile_path)
        if password in cache:
            return cache[password]
    return generate_ntlm_hash(password)


def generate_sid(domain_sid_base: str, rid: int) -> str:
    """Generate a SID."""
    return f"{domain_sid_base}-{rid}"


def generate_date(days_ago_min: int, days_ago_max: int) -> str:
    """Generate a random date string."""
    days_ago = random.randint(days_ago_min, days_ago_max)
    date = datetime.now() - timedelta(days=days_ago)
    return date.strftime("%m/%d/%Y %I:%M:%S %p")


def generate_users(potfile_path: str) -> tuple[List[Dict[str, Any]], Dict[str, str]]:
    """
    Generate user accounts using real hashes from the potfile.

    Args:
        potfile_path: Path to potfile with hash:password pairs

    Returns:
        Tuple of (users list, hash_to_password dict for potfile output)
    """
    # Load existing potfile, excluding sensitive passwords
    potfile_entries = []  # List of (hash, password) tuples
    try:
        with open(potfile_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2 and len(parts[0]) == 32:
                        password = parts[1]
                        if password not in EXCLUDED_PASSWORDS:
                            potfile_entries.append((parts[0].lower(), password))
    except FileNotFoundError:
        print(f"Warning: Potfile not found at {potfile_path}")

    print(f"  Loaded {len(potfile_entries)} hash:password pairs from potfile")

    users = []
    hash_to_password = {}  # For output potfile
    used_usernames = set()
    used_hashes = set()
    rid_counter = 1001
    domain_sid = "S-1-5-21-1234567890-1234567890-1234567890"

    # Blank password hash
    BLANK_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

    # Built-in accounts
    builtin_accounts = [
        ("Administrator", "Domain Admins", True, True),   # cracked
        ("Guest", "", False, "blank"),                     # blank password
        ("krbtgt", "", False, False),                      # not cracked
        ("DefaultAccount", "", False, "blank"),            # blank password
    ]

    for username, group, enabled, cracked_status in builtin_accounts:
        if cracked_status == "blank":
            ntlm_hash = BLANK_HASH
            password = ""
        elif cracked_status and potfile_entries:
            # Use a real hash from potfile
            entry = potfile_entries[len(users) % len(potfile_entries)]
            ntlm_hash, password = entry
            hash_to_password[ntlm_hash] = password
        else:
            ntlm_hash = ''.join(random.choices('0123456789abcdef', k=32))
            password = None

        user = create_user(
            username=username,
            first="",
            last="",
            department="System",
            rid=rid_counter,
            domain_sid=domain_sid,
            enabled=enabled,
            is_admin=(group == "Domain Admins"),
            ntlm_hash=ntlm_hash,
            is_service=True,
        )
        users.append(user)
        used_hashes.add(ntlm_hash)
        rid_counter += 1
        used_usernames.add(username.lower())

    # Service accounts - use real hashes with Kerberoast-related attributes
    for svc_name, config in SERVICE_ACCOUNT_CONFIGS.items():
        # Determine if this service account should be cracked (70% for demos)
        is_cracked = random.random() < 0.7

        if is_cracked and potfile_entries:
            entry = potfile_entries[len(users) % len(potfile_entries)]
            ntlm_hash, password = entry
            hash_to_password[ntlm_hash] = password
        else:
            ntlm_hash = ''.join(random.choices('0123456789abcdef', k=32))

        # Resolve domain placeholder in SPNs and delegation targets
        spns = [s.format(domain=DOMAIN) for s in config["spns"]]
        delegation_targets = [t.format(domain=DOMAIN) for t in config.get("delegation_targets", [])]

        # Some service accounts have stale passwords (3+ years)
        pwd_age = None
        if random.random() < 0.3:  # 30% have stale passwords
            pwd_age = random.randint(1095, 2000)  # 3-5.5 years

        user = create_user(
            username=svc_name,
            first="",
            last="",
            department="IT",
            rid=rid_counter,
            domain_sid=domain_sid,
            enabled=True,
            is_admin=config.get("privileged", False),
            ntlm_hash=ntlm_hash,
            is_service=True,
            description=config["description"],
            spns=spns,
            delegation_targets=delegation_targets,
            enc_types=config.get("enc_types", ""),
            password_never_expires=True,  # Service accounts typically have this
            pwd_age_days=pwd_age,
        )
        users.append(user)
        used_hashes.add(ntlm_hash)
        rid_counter += 1
        used_usernames.add(svc_name.lower())

    # Add krbtgt with its special SPN
    krbtgt_user = create_user(
        username="krbtgt",
        first="",
        last="",
        department="System",
        rid=502,  # Standard RID for krbtgt
        domain_sid=domain_sid,
        enabled=False,  # krbtgt is always disabled
        is_admin=False,
        ntlm_hash=''.join(random.choices('0123456789abcdef', k=32)),
        is_service=True,
        description="Key Distribution Center Service Account",
        spns=["kadmin/changepw"],
        enc_types="0",
    )
    users.append(krbtgt_user)
    rid_counter += 1

    # Add a few AS-REP roastable accounts (preauth disabled)
    asrep_accounts = ["legacy_app", "old_service", "test_account"]
    for username in asrep_accounts:
        is_cracked = random.random() < 0.5
        if is_cracked and potfile_entries:
            entry = potfile_entries[len(users) % len(potfile_entries)]
            ntlm_hash, password = entry
            hash_to_password[ntlm_hash] = password
        else:
            ntlm_hash = ''.join(random.choices('0123456789abcdef', k=32))

        user = create_user(
            username=username,
            first="",
            last="",
            department="IT",
            rid=rid_counter,
            domain_sid=domain_sid,
            enabled=True,
            is_admin=False,
            ntlm_hash=ntlm_hash,
            is_service=False,
            description="Legacy account with pre-auth disabled",
            preauth_not_required=True,
            password_never_expires=True,
            pwd_age_days=random.randint(730, 1500),  # 2-4 years old
        )
        users.append(user)
        used_hashes.add(ntlm_hash)
        rid_counter += 1
        used_usernames.add(username.lower())

    # Add an account with unconstrained delegation (dangerous)
    uncon_user = create_user(
        username="fileserver_svc",
        first="",
        last="",
        department="IT",
        rid=rid_counter,
        domain_sid=domain_sid,
        enabled=True,
        is_admin=False,
        ntlm_hash=''.join(random.choices('0123456789abcdef', k=32)),
        is_service=True,
        description="File Server Service Account - Unconstrained Delegation",
        spns=[f"cifs/fileserver.{DOMAIN}", f"HOST/fileserver.{DOMAIN}"],
        unconstrained_delegation=True,
        password_never_expires=True,
        enc_types="4",  # RC4 only - legacy
    )
    users.append(uncon_user)
    rid_counter += 1

    # Computer accounts
    for i in range(20):
        comp_name = f"WORKSTATION{i+1:03d}$"
        user = create_user(
            username=comp_name,
            first="",
            last="",
            department="Computers",
            rid=rid_counter,
            domain_sid=domain_sid,
            enabled=True,
            is_computer=True,
        )
        users.append(user)
        rid_counter += 1

    # Create reuse groups (10-20 groups of 2-8 users sharing same hash)
    reuse_hashes = []  # List of hashes to reuse
    if potfile_entries:
        num_reuse_groups = random.randint(10, 20)
        reuse_hashes = random.sample(potfile_entries, min(num_reuse_groups, len(potfile_entries)))

    reuse_assignments = {}  # hash -> [list of target count, current count]
    for ntlm_hash, password in reuse_hashes:
        target = random.randint(2, 8)
        reuse_assignments[ntlm_hash] = {"target": target, "count": 0, "password": password}
        hash_to_password[ntlm_hash] = password

    # Generate department users
    potfile_index = 0

    for dept, config in DEPARTMENTS.items():
        target_count = config["count"]
        admin_ratio = config["admin_ratio"]

        for i in range(target_count):
            # Generate unique username
            attempts = 0
            while attempts < 100:
                first = random.choice(FIRST_NAMES)
                last = random.choice(LAST_NAMES)
                username = f"{first[0].lower()}{last.lower()}"
                if len(username) > 15:
                    username = username[:15]
                if username not in used_usernames:
                    used_usernames.add(username)
                    break
                username = f"{first[0].lower()}{last.lower()}{random.randint(1,99)}"
                if username not in used_usernames:
                    used_usernames.add(username)
                    break
                attempts += 1

            if attempts >= 100:
                continue

            is_admin = random.random() < admin_ratio
            is_cracked = random.random() < CRACK_RATE_TARGET
            is_disabled = random.random() < 0.05
            is_expired = random.random() < 0.03
            has_lm = random.random() < 0.02
            is_blank = random.random() < 0.01  # 1% blank passwords

            if is_blank:
                ntlm_hash = BLANK_HASH
                hash_to_password[ntlm_hash] = ""
            elif is_cracked and potfile_entries:
                # Check if should be in a reuse group
                assigned_to_reuse = False
                for reuse_hash, data in reuse_assignments.items():
                    if data["count"] < data["target"]:
                        ntlm_hash = reuse_hash
                        data["count"] += 1
                        assigned_to_reuse = True
                        break

                if not assigned_to_reuse:
                    # Use unique hash from potfile
                    entry = potfile_entries[potfile_index % len(potfile_entries)]
                    ntlm_hash, password = entry
                    hash_to_password[ntlm_hash] = password
                    potfile_index += 1
            else:
                # Not cracked - random hash
                ntlm_hash = ''.join(random.choices('0123456789abcdef', k=32))

            user = create_user(
                username=username,
                first=first,
                last=last,
                department=dept,
                rid=rid_counter,
                domain_sid=domain_sid,
                enabled=not is_disabled,
                is_admin=is_admin,
                ntlm_hash=ntlm_hash,
                has_lm=has_lm,
                expired=is_expired,
            )
            users.append(user)
            rid_counter += 1

    return users, hash_to_password


def create_user(
    username: str,
    first: str,
    last: str,
    department: str,
    rid: int,
    domain_sid: str,
    enabled: bool = True,
    is_admin: bool = False,
    is_service: bool = False,
    is_computer: bool = False,
    password: str = None,
    ntlm_hash: str = None,
    has_lm: bool = False,
    expired: bool = False,
    description: str = "",
    spns: List[str] = None,
    delegation_targets: List[str] = None,
    enc_types: str = "",
    password_never_expires: bool = False,
    preauth_not_required: bool = False,
    unconstrained_delegation: bool = False,
    pwd_age_days: int = None,
) -> Dict[str, Any]:
    """Create a user account dictionary with Kerberoast-related fields."""

    # Use provided hash or generate one
    if ntlm_hash:
        pass  # Use provided hash
    elif password == "":
        # Blank password
        ntlm_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
    elif password is None:
        # Random hash (not cracked)
        ntlm_hash = ''.join(random.choices('0123456789abcdef', k=32))
    else:
        ntlm_hash = generate_ntlm_hash(password)

    # Build group memberships
    groups = []
    if is_admin:
        groups.extend(["Domain Admins", "Administrators"])
    if is_service:
        groups.append("Service Accounts")
    if department == "IT":
        groups.append("IT Staff")
    if department == "Executive":
        groups.extend(["Executives", "VIP Users"])
    groups.append("Domain Users")

    # Build UAC flags
    uac = []
    if is_computer:
        uac.append("WORKSTATION_TRUST_ACCOUNT")
    else:
        uac.append("NORMAL_ACCOUNT")
    if not enabled:
        uac.append("ACCOUNTDISABLE")
    if expired:
        uac.append("PASSWORD_EXPIRED")
    if password == "":
        uac.append("PASSWD_NOTREQD")
    if password_never_expires:
        uac.append("DONT_EXPIRE_PASSWORD")
    if preauth_not_required:
        uac.append("DONT_REQ_PREAUTH")
    if unconstrained_delegation:
        uac.append("TRUSTED_FOR_DELEGATION")
    if delegation_targets:
        uac.append("TRUSTED_TO_AUTH_FOR_DELEGATION")

    # Calculate RawUACValue from flags
    uac_values = {
        "NORMAL_ACCOUNT": 0x200,
        "ACCOUNTDISABLE": 0x002,
        "PASSWORD_EXPIRED": 0x800000,
        "PASSWD_NOTREQD": 0x020,
        "DONT_EXPIRE_PASSWORD": 0x10000,
        "DONT_REQ_PREAUTH": 0x400000,
        "TRUSTED_FOR_DELEGATION": 0x80000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
        "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    }
    raw_uac = sum(uac_values.get(flag, 0) for flag in uac)

    # Generate dates
    created_days_ago = random.randint(30, 1800)
    changed_days_ago = random.randint(1, min(created_days_ago, 365))

    # Password age - use provided value or random
    if pwd_age_days is not None:
        pwd_last_set_days = pwd_age_days
    else:
        pwd_last_set_days = random.randint(1, 180)

    user = {
        "Cn": username,
        "Name": username,
        "First": first,
        "Last": last,
        "SamAccountName": username,
        "GroupMemberCount": str(len(groups)),
        "MemberOf": groups,
        "DisplayName": f"{first} {last}".strip() if first else username,
        "PrimaryGroupId": "515" if is_computer else "513",
        "WhenCreated": generate_date(created_days_ago, created_days_ago + 30),
        "WhenChanged": generate_date(changed_days_ago, changed_days_ago + 10),
        "LastLogon": generate_date(0, 30) if enabled else "",
        "UserAccountControl": uac,
        "RawUACValue": str(raw_uac),
        "PwdLastSet": generate_date(pwd_last_set_days, pwd_last_set_days + 10),
        "LockoutTime": "",
        "ObjectSid": generate_sid(domain_sid, rid),
        "Description": description or (f"{department} user" if department else ""),
        "NTLMHash": ntlm_hash,
        "HistoricalNTHashes": [],
        "LogonName": f"{DOMAIN}\\{username}",
        # Kerberoast-related fields
        "ServicePrincipalNames": spns or [],
        "adminCount": "1" if is_admin else "0",
        "supportedEncryptionTypes": enc_types,
        "allowedToDelegateTo": delegation_targets or [],
        "DistinguishedName": f"CN={username},OU={'Computers' if is_computer else 'Users'},DC={DOMAIN.split('.')[0]},DC={DOMAIN.split('.')[1]}",
    }

    # Add LM hash if applicable
    if has_lm:
        user["LMHash"] = generate_lm_hash()

    return user


def build_password_pool() -> List[str]:
    """Build a pool of passwords to use."""
    pool = []

    # Add bad practice passwords (weighted heavily)
    for category, passwords in BAD_PRACTICE_PASSWORDS.items():
        pool.extend(passwords * 3)  # Triple weight

    # Add short passwords
    pool.extend(SHORT_PASSWORDS * 5)  # Higher weight for testing

    # Add simple passwords
    pool.extend(SIMPLE_PASSWORDS * 5)

    # Add some variants
    variants = []
    for pw in pool[:50]:
        # Add year variants
        if "2024" in pw:
            variants.append(pw.replace("2024", "2023"))
            variants.append(pw.replace("2024", "2025"))
        # Add case variants
        variants.append(pw.lower())
        variants.append(pw.upper())
    pool.extend(variants)

    return pool


def create_reuse_groups(password_pool: List[str]) -> Dict[str, List]:
    """Create password reuse groups."""
    groups = {}

    # Select some passwords to be reused
    reuse_passwords = random.sample(password_pool[:30], 15)

    for pw in reuse_passwords:
        # Target size for reuse group (2-8 users)
        target_size = random.randint(2, 8)
        groups[pw] = [target_size]  # First element is target size

    return groups


def create_add_json(users: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create the full ADD JSON structure."""
    return {
        "Name": DOMAIN,
        "PullDate": datetime.now().strftime("%m/%d/%Y %I:%M:%S %p"),
        "UserCount": str(len(users)),
        "MinPwdAge": "1",
        "MaxPwdAge": "90",
        "MinPasswordLength": "12",
        "PwdProperties": "1",
        "LockoutDuration": "30",
        "LockoutObservationWindow": "30",
        "LockoutThreshold": "5",
        "PwdHistoryLength": "24",
        "DomainTrusts": [],
        "Users": users,
    }


def create_potfile(hash_to_password: Dict[str, str]) -> str:
    """Create potfile content."""
    lines = []
    for ntlm_hash, password in hash_to_password.items():
        lines.append(f"{ntlm_hash}:{password}")
    return "\n".join(lines)


def main():
    """Main function."""
    print("=" * 60)
    print("Demo Dataset Generator for Hash Master 1000")
    print("=" * 60)

    # Paths
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent
    potfile_path = project_dir / "data" / "master.potfile"

    if not potfile_path.exists():
        print(f"Error: Master potfile not found at {potfile_path}")
        return

    # Generate users
    print("\nGenerating users...")
    users, hash_to_password = generate_users(str(potfile_path))

    # Count stats
    total = len(users)
    cracked = len(hash_to_password)
    computer_accounts = len([u for u in users if "$" in u["SamAccountName"]])
    admin_accounts = len([u for u in users if "Domain Admins" in u.get("MemberOf", [])])
    disabled_accounts = len([u for u in users if "ACCOUNTDISABLE" in u.get("UserAccountControl", [])])
    blank_passwords = len([u for u in users if u["NTLMHash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"])

    # Kerberoast-related stats
    service_accounts = len([u for u in users if u.get("ServicePrincipalNames")])
    kerberoastable = len([u for u in users
                         if u.get("ServicePrincipalNames")
                         and not u["SamAccountName"].endswith("$")
                         and u["SamAccountName"].lower() != "krbtgt"
                         and "ACCOUNTDISABLE" not in u.get("UserAccountControl", [])])
    asrep_roastable = len([u for u in users if "DONT_REQ_PREAUTH" in u.get("UserAccountControl", [])])
    with_delegation = len([u for u in users
                          if u.get("allowedToDelegateTo")
                          or "TRUSTED_FOR_DELEGATION" in u.get("UserAccountControl", [])])
    privileged_svc = len([u for u in users
                         if u.get("ServicePrincipalNames") and u.get("adminCount") == "1"])

    print(f"  Total accounts: {total}")
    print(f"  Cracked passwords: {cracked} ({cracked/total*100:.1f}%)")
    print(f"  Computer accounts: {computer_accounts}")
    print(f"  Admin accounts: {admin_accounts}")
    print(f"  Disabled accounts: {disabled_accounts}")
    print(f"  Blank passwords: {blank_passwords}")
    print(f"\n  Kerberoast-related:")
    print(f"    Service accounts (with SPNs): {service_accounts}")
    print(f"    Kerberoastable (enabled, non-computer): {kerberoastable}")
    print(f"    AS-REP roastable: {asrep_roastable}")
    print(f"    With delegation: {with_delegation}")
    print(f"    Privileged service accounts: {privileged_svc}")

    # Create output directory
    test_data_dir = project_dir / "testData"
    test_data_dir.mkdir(exist_ok=True)

    # Save ADD JSON
    add_json = create_add_json(users)
    add_path = test_data_dir / "example_ADD_expanded.json"
    with open(add_path, 'w') as f:
        json.dump(add_json, f, indent=2)
    print(f"\nSaved ADD JSON to: {add_path}")

    # Save potfile
    potfile_content = create_potfile(hash_to_password)
    potfile_path = test_data_dir / "example_expanded.potfile"
    with open(potfile_path, 'w') as f:
        f.write(potfile_content)
    print(f"Saved potfile to: {potfile_path}")
    print(f"  {len(hash_to_password)} entries")

    print("\n" + "=" * 60)
    print("Done! To test:")
    print(f"  1. Load {add_path.name} as the ADD JSON")
    print(f"  2. Load {potfile_path.name} as the potfile")
    print("=" * 60)


if __name__ == "__main__":
    main()
