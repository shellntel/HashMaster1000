#!/usr/bin/env python3
"""
Generate a comprehensive test file for Hash Master 1000 QA testing.
This creates example_dcsync.txt with 1000+ accounts across 4 domains.
"""

# Cracked hashes from example.potfile (NTLM hash -> password)
CRACKED_HASHES = {
    "01fda8996358026baa397fe2c34b8e31": "Summertime2023",       # len=13
    "06ce731f0957229c0b3060622caa3429": "Red4spring",           # len=10
    "07ee4fe4435c4d265f1b76f07bd8ca51": "Password002$$",        # len=13
    "09fb5dda3f095a3e0c7f024f38dd267e": "Springfield1!",        # len=12
    "0a2302ddf9a2bec00bd3147bd7cbd99d": "Password72*",          # len=11
    "0c1e904c7e63a0fbe7ff6f5a4eef1375": "$Password1",           # len=10
    "0d5d5a678af6be6d6de025e9e6aa03e7": "Fall2022!",            # len=9
    "12dc32669b9dc00106511dd579fb33fd": "20springtime",         # len=12
    "13f386382f3709af2cd50171a6a5b8a4": "2020Winter!",          # len=11
    "14690aafe27969ecf3158707d8c67515": "Summertime2022",       # len=14
    "1570959084b38ba922793ee1c7cd0bd4": "Fallon4291",           # len=10
    "15eac911fa04058ebdf0e83d2a53433c": "Password#1",           # len=10
    "1628488e442316500a176701e0ac3c54": "Summer2021",           # len=10
    "1b4ed622e07d1dc49782a04fb9e92c20": "Fall$0628",            # len=9
    "1c4f667174b6e1fed7008f447ca0ade2": "Fall2018!!",           # len=10
    "1d8f83ef1153470995ee656562f4a3c1": "1password!",           # len=10
    "1e09a46bffe68a4cb738b0381af1dc96": "Spring2022",           # len=10
    "1ed015b2f3dc54deabb3a5e3b20fd655": "Password3030!",        # len=13
    "24b4f0e1a9408c42733593c3efa84bc3": "Winter2006#",          # len=11
    "261b7ae9fae48e831bf69def8a3dff42": "Winter1102",           # len=10
    "29ab86c5c4d2aab957763e5c1720486d": "Password1234!",        # len=13
    "2553c452801e6e81e8badcfca61daf99": "summer2022*",          # len=11
    "2eba0955fc1e3b6b03c2ff4b3e9fcbbf": "Spring2023#",          # len=11
    "307bbcfc3b4e38e066b46fa377893d4d": "Password06",           # len=10
    "30a1e3ecf2d9c5048330e74337dc15e5": "Summer2022?",          # len=11
    "31b1f230566bae6a554c8b0470e98b06": "Stupidpassword01!",    # len=17
    "31d6cfe0d16ae931b73c59d7e0c089c0": "",                     # BLANK PASSWORD
    "349c161a3eb493c6347292a58528f923": "Summer2024",           # len=10
    "3c1170930a37f0592e2957c2089d0fac": "Falltime2022",         # len=12
    "3c4ae58e173aa89a65eb1f1a0378746d": "Ktspassword12!",       # len=14
    "3fde712fddc8eab43bbaf737f57093de": "Springtime01",         # len=12
    "40ac18774659424d92180ba570ac27b3": "Falltime22",           # len=10
    "41dcb74a324e41506cb637c37168744d": "Candy35fall",          # len=11
    "4210e68078724566518b8ad3f197a4a6": "Summer2023",           # len=10
    "427fbae0cd25256f4c2931740993032d": "Springfield23",        # len=13
    "431073161988600bbb0a7f227cc4c58b": "Springvale3",          # len=11
    "436208ad330cef63405cb5071a695ce3": "Fall2022!!",           # len=10
    "43b80e99dd98fd05c1205299d0c9f7b1": "2Manypasswords",       # len=14
    "47dd446a80512414185572b2e76a47da": "New@password",         # len=12
    "4c3879fef394fa5dce0037c197c70841": "Winter2021",           # len=10
    "4db01a4b900ca760465a0714249049de": "Winter2022*",          # len=11
    "4dc2fec689ab309dd606fb737eb214a6": "Falltime22!",          # len=11
    "4ea072db1483a7df8643772b6b25cb43": "Summer2023!",          # len=11
    "511c41fc145135fa2b2232311eeba597": "Summer2022!!",         # len=12
    "535baf9cf1c3067f9e952cc093f47cea": "Spring2019",           # len=10
    "5362ab7642c08ecd687773f5a9b792a1": "Falltime123",          # len=11
    "57912afe60e9274c35672bf526baed61": "Spring2021",           # len=10
    "5835048ce94ad0564e29a924a03510ef": "password1",            # len=9
    "59204fcee737084593be90715e8dffc8": "Changepassword",       # len=14
    "5ad8dfa79777ae85e3a9198994afc79b": "Winter2026",           # len=10
    "5c3536eb8a3cba820c9b4f0aea3d12bc": "Summer2022!",          # len=11
    "5f695056521900e992a6366aabb446a3": "Summer2025",           # len=10
    "632b06c75304ab6d074b8ed8b73cf98b": "Password02",           # len=10
    "63ccdc735b27ae079d5956fa2f471aea": "Fall2022",             # len=8
    "64f12cddaa88057e06a81b54e73b949b": "Password1",            # len=9
    "6764fe28542b7c8bc6f0f60a6bcd94de": "Carespring1!",         # len=12
    "68b420f0ecc7f5b7c883378095bf5a8a": "Summer2022@",          # len=11
    "6d4813bddc13f670963bac2f6d88707c": "Winter20220",          # len=11
    "6e1e8679b14cf3a9f03b30710519925b": "Password10!",          # len=11
    "6f6991e9dc358d5bc40b04714091ce1d": "Winter2021$",          # len=11
    "70586bc2191f0a0872798bcb30c7fcdf": "Winter2019",           # len=10
    "7142190f3122b1a00e914af7a5426900": "Password!227",         # len=12
    "78c293b80ebb33b2a5a420f3761f69c6": "Carespring2!",         # len=12
    "794df6c082f0ed6d415072bad04df2a3": "Spring2024",           # len=10
    "7978dc8a66d8e480d9a86041f8409560": "Winter2022",           # len=10
    "7c5f2dc7acb81e902958bfdee467e4f0": "NAPassword#1",         # len=12
    "7df1dfb1d2e5243d0f116973b92e1aee": "Winter2022#",          # len=11
    "7f064a585df3a166fd8ce4743adba658": "Summer2022+",          # len=11
    "7facdc498ed1680c4fd1448319a8c04f": "Password1!",           # len=10
    "80fbdb0d29b0de3f0e040a3450e10c14": "Winter2222",           # len=10
    "81ea26d4212f73125d38f9999c98252e": "Summer2020!",          # len=11
    "834070995136be54edfd8bd8dce43945": "Spring2020*",          # len=11
    "83c4be1a3fd33a182dafc8bd3bf53d00": "winter2022!",          # len=11
    "871c94500d1d3aa620d316016b9e6e68": "Password2609!",        # len=13
    "8846f7eaee8fb117ad06bdd830b7586c": "password",             # len=8
    "89cdf00b5bd63aba309f7c3ee8d5dd50": "Winter2018",           # len=10
    "8a969c08c289fecfea806e61fbf78697": "Summer2020!!!!!!!",    # len=17
    "8be5954aed20ffe8341e4ab8ed805f83": "Thispasswordislong1!", # len=20
    "936fe75624c2518a011b1ee85a6dcb2b": "Summer2022$",          # len=11
    "960248305484709b3c0a0eb6af854991": "Password501$",         # len=12
    "98f1aa05d390f3fbeeda31019719f7ca": "Winter1234",           # len=10
    "9af0e42138461e37f88ab5f368f04954": "#Password2020",        # len=13
    "9d218b01d74c969b09c17d57189e01ff": "Summer2021!",          # len=11
    "9e6fa0decb76c043432493fa214d9b76": "Summer2022*",          # len=11
    "a243ea0a666107e5946362230e328cf3": "Spring2023",           # len=10
    "a3d7d25665f1146b56192b850fd57a93": "Summer2022",           # len=10
    "a42f287a6e271b0b1413b317335d2f42": "Winter*123",           # len=10
    "a4012bd10a3f8a78e0d0348c57356ca0": "Winter@12345",         # len=12
    "a611f2ae0654260ee0e6f533e9f5640e": "Fall202232",           # len=10
    "a656a1aba1dfd5d4bd62d6a968e41fe1": "Fall09091981",         # len=12
    "a882591c875ae54533fc6f14fa6173ce": "Summer2020$",          # len=11
    "a92c984729c5f5ef6d1d4a3c24232537": "Fall@2022!",           # len=10
    "a9ec317c0ea027fb6dbbe8ea66ee11ee": "Starfall13",           # len=10
    "acbfc03df96e93cf7294a01a6abbda33": "Summer2020",           # len=10
    "b0353d8fafd1e17091aa12b0d2d4efde": "Changepassword2022$",  # len=19
    "b1a9d23b0a71995e3032498e098974d3": "Winter4444",           # len=10
    "b23b63f32e102c28c256fd0cf7728456": "Password1*",           # len=10
    "b35b754c7ac2aaf64ad36cfcb58c7789": "Summer2022#",          # len=11
    "bfc1e1e00991f2ad57cd8cb928884eb9": "Ihatepasswords1!",     # len=16
    "c24f45fdbc32136b98c9cce69845c07b": "Winter1984",           # len=10
    "c27149acc73d20ff480552af6b9a3907": "Spring2020!!!",        # len=13
    "c69bdf481e186667242a76888f096a64": "Springtime1",          # len=11
    "ce65b937acc7baffc2ba667874501f0a": "summer2022.",          # len=11
    "cf3cdaa41c730bcb465c0ec53590724f": "4Summer2022",          # len=11
    "d388e46256004b4d6de7b482a8f1a5f5": "Springtime22",         # len=12
    "d7481936003558c1bf7d9985dd2cb7e3": "Fall2022**",           # len=10
    "d8eec70f02f3ccfef2e2756c1177f97a": "Fallll2022",           # len=10
    "daa4e39a22771b89bbe482c83e4ae507": "Winter2022%",          # len=11
    "dccad76865fd0d66b6f6480f61a4f77a": "!Summer2022",          # len=11
    "e2e3e4693a5ac4c963ddc0ce9ffaf110": "Winteriscoming!",      # len=15
    "e4832d07198abbe0ac236c060704644f": "Winter1984!",          # len=11
    "e63f018c5a2687fb4b88bc8a485a5145": "Fall22221!",           # len=10
    "e8db3bccab288ead4aba1aa740e8cb72": "Carespring22",         # len=12
    "eb6538aa406cfad09403d3bb1f94785f": "Winter2018!",          # len=11
    "ec7a94a17bc96fb4d5d95db56e525043": "Winter2023",           # len=10
    "f14eee53c480f0063acc5ba8f026457b": "password#1",           # len=10
    "f189b64460941c4b1609bc6910978e63": "Fall2022!@",           # len=10
    "f4a1e7c0d2967c13dc50e08e90b41108": "Ihatepasswords!16",    # len=17
    "f6e4e3339ce1d87b4f0fbf8327f83524": "Coldwinter22",         # len=12
    "fb4d2b115e27b3662b10a3f2c2d750ce": "Redwinter22",          # len=11
    "fcb63becd811c9a6fd9661939563b1ba": "Password1.",           # len=10
    "fd23e367c3cb58b6a8d9fef62f48f40c": "Winter2121",           # len=10
    "fe8e78c9435c68cf0e4634a5d37ea00d": "Spring2023!!",         # len=12
    "fea80c63aed12d5aef0808c5b0d9a782": "Spring2022!",          # len=11
    "bbfebe105a4b28dc1d6385d611d80ad8": "Ilovespring!?",        # len=13
    "6aca0b9cfd74ea42a546973c4c4b40bf": "Carespring5000",       # len=14
    "285b29144c4982699f2ae22d9d1b7d67": "Fallcolors2022",       # len=14
    "171077dc7dbfe4ad00eb12f784b89a7e": "Fallfun2212!",         # len=12
    "c8266790573761fd2cb8bf33573c9dfe": "Fallisintheair@22",    # len=17
    "9554d5f34d683f39a9d4fe6c66fe0018": "Passwordhell19!",      # len=15
    "9ceb21a33f93d0ed236bcd381c27a0bc": "Thisisnotagoodpassword1",  # len=23
    "3289d111cc9dfd0ae3bd57c01c521354": "Fall2022+1",           # len=10
    "a3a8397b7df8b16f2d6bd9fe27d9c73d": "Fall2474!!",           # len=10
    "9fe8cf829900934f8311aa72bf9a8470": "FallRN2022",           # len=10
    "7a6e59ca1848d105b8c787d411d7bc59": "FallRN2022!",          # len=11
}

# Generate many unique uncracked hashes deterministically
# We need ~525 unique uncracked hashes for the 50% that don't crack
def generate_uncracked_hashes(count):
    """Generate deterministic fake NTLM hashes that won't be in the potfile."""
    import hashlib
    hashes = []
    for i in range(count):
        # Create a deterministic but unique hash based on index
        seed = f"uncracked_password_{i:05d}_hm1k_test"
        h = hashlib.md5(seed.encode()).hexdigest()
        hashes.append(h)
    return hashes

# Generate 600 unique uncracked hashes (more than we need to ensure variety)
UNCRACKED_HASHES = generate_uncracked_hashes(600)

# Non-blank LM hashes for variety
LM_HASHES = [
    "e52cac67419a9a224a3b108f3fa6cb6d",  # Has LM hash (password)
    "e57ec0c178d74e4c3a7e9d1b2c0f5a8d",
    "d87f0c7a82e4f9d53c6b4a810e2f793c",
    "c4a3b9f8d267e5c0f4912d3a8b7c6e10",
    "b3c8d9e2f1a047658c3d92e7f0b6a514",
]

# Domains with their distribution
DOMAINS = {
    "example.com": 250,    # ~25%
    "acme.corp": 300,      # ~30%
    "company.net": 280,    # ~28%
    "contoso.com": 220,    # ~22% (includes most computer accounts)
}

# First names for generating usernames
FIRST_NAMES = [
    "James", "Michael", "Robert", "John", "David", "William", "Richard", "Joseph",
    "Thomas", "Christopher", "Charles", "Daniel", "Matthew", "Anthony", "Mark",
    "Donald", "Steven", "Andrew", "Paul", "Joshua", "Kenneth", "Kevin", "Brian",
    "Timothy", "Ronald", "George", "Jason", "Edward", "Jeffrey", "Ryan",
    "Jacob", "Nicholas", "Gary", "Eric", "Jonathan", "Stephen", "Larry", "Justin",
    "Scott", "Brandon", "Benjamin", "Samuel", "Gregory", "Alexander", "Patrick",
    "Frank", "Raymond", "Jack", "Dennis", "Jerry", "Tyler", "Aaron", "Jose",
    "Adam", "Nathan", "Henry", "Douglas", "Zachary", "Peter", "Kyle",
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan",
    "Jessica", "Karen", "Sarah", "Lisa", "Nancy", "Sandra", "Betty", "Ashley",
    "Emily", "Kimberly", "Margaret", "Donna", "Michelle", "Carol", "Amanda",
    "Melissa", "Deborah", "Stephanie", "Rebecca", "Sharon", "Laura", "Cynthia",
    "Dorothy", "Amy", "Kathleen", "Angela", "Shirley", "Emma", "Brenda", "Pamela",
    "Nicole", "Anna", "Samantha", "Katherine", "Christine", "Debra", "Rachel",
    "Carolyn", "Janet", "Maria", "Olivia", "Heather", "Helen", "Catherine",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzales", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen",
    "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera",
    "Campbell", "Mitchell", "Carter", "Roberts", "Gomez", "Phillips", "Evans",
    "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart",
    "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan",
    "Cooper", "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim",
    "Cox", "Ward", "Richardson", "Watson", "Brooks", "Chavez", "Wood", "James",
    "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes", "Price", "Alvarez", "Castillo",
    "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez",
]

# Blank LM hash constant
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"
BLANK_NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"


def main():
    accounts = []
    stats = {
        "total_accounts": 0,
        "user_accounts": 0,
        "computer_accounts": 0,
        "enabled_accounts": 0,
        "disabled_accounts": 0,
        "blank_passwords": 0,
        "non_blank_lm_hashes": 0,
        "cracked_accounts": 0,
        "uncracked_accounts": 0,
        "shared_passwords": {},  # hash -> count
        "password_lengths": {},  # length -> count
        "by_domain": {},
        "dcsync_format": 0,
        "standard_format": 0,
    }

    # Initialize domain stats
    for domain in DOMAINS:
        stats["by_domain"][domain] = {
            "total": 0,
            "enabled": 0,
            "disabled": 0,
            "computer": 0,
            "cracked": 0,
            "blank": 0,
        }

    cracked_hash_list = list(CRACKED_HASHES.keys())
    cracked_hash_list.remove(BLANK_NTLM)  # Remove blank from regular cracked list

    # We have ~143 cracked hashes (excluding blank)
    # Strategy for 25 reused passwords (including blank):
    # - 1 blank password (25 accounts)
    # - 24 reused cracked passwords from the end of the list
    # All other cracked hashes will be used exactly once

    # Split the hash list: first hashes for unique use, last 24 for reuse
    reused_hashes = cracked_hash_list[-24:]  # Last 24 hashes will be reused
    unique_cracked_hashes = cracked_hash_list[:-24]  # Rest are for unique use only

    line_num = 0
    unique_hash_idx = 0  # Counter for unique cracked hashes
    username_set = set()  # Track used usernames to avoid duplicates

    # Create a deterministic list of accounts
    for domain, count in DOMAINS.items():
        domain_users = 0
        domain_computers = 0

        while domain_users + domain_computers < count:
            # Determine if this is a computer account (contoso gets most)
            is_computer = False
            if domain == "contoso.com" and domain_computers < 35:
                # 35 computer accounts in contoso.com
                is_computer = (domain_users + domain_computers) % 5 == 0 and domain_computers < 35
            elif domain != "contoso.com" and domain_computers < 5:
                # 5 computer accounts per other domain
                is_computer = (domain_users + domain_computers) % 40 == 0 and domain_computers < 5

            # Generate username
            if is_computer:
                computer_name = f"WORKSTATION{line_num:04d}"
                username = f"{computer_name}$"
                domain_computers += 1
            else:
                # Generate unique First.Last username
                fname_idx = (line_num * 7) % len(FIRST_NAMES)
                lname_idx = (line_num * 13) % len(LAST_NAMES)
                base_username = f"{FIRST_NAMES[fname_idx]}.{LAST_NAMES[lname_idx]}"

                # Ensure uniqueness within domain
                username = base_username
                suffix = 1
                while f"{domain}\\{username}" in username_set:
                    username = f"{base_username}{suffix}"
                    suffix += 1
                domain_users += 1

            full_username = f"{domain}\\{username}"
            if full_username in username_set:
                line_num += 1
                continue
            username_set.add(full_username)

            # Determine enabled/disabled status (80% enabled, 20% disabled)
            # All accounts use dcsync format with status
            use_dcsync = True
            is_enabled = (line_num % 5) != 0  # 80% enabled

            # Determine hash assignment
            # Goals:
            # - 50% of accounts should crack (~525)
            # - Max 25 passwords can be reused (shared by >1 account)
            # - 25 blank passwords, 20 non-blank LM hashes
            #
            # Strategy:
            # - 25 blank passwords (1 hash reused 25 times) -> reused password #1
            # - 20 with non-blank LM hashes (unique cracked hashes)
            # - 525 uncracked accounts (525 unique hashes)
            # - Remaining cracked accounts:
            #   - First use all remaining unique cracked hashes (each once)
            #   - Then use 24 reused hashes for the rest -> reused passwords #2-25

            if line_num < 25:
                # First 25 get blank passwords (these are cracked - empty string)
                # This is reused password #1
                ntlm_hash = BLANK_NTLM
                lm_hash = BLANK_LM
            elif line_num < 45:
                # Next 20 get non-blank LM hashes with unique cracked passwords
                lm_hash = LM_HASHES[(line_num - 25) % len(LM_HASHES)]
                # Use next unique hash
                ntlm_hash = unique_cracked_hashes[unique_hash_idx]
                unique_hash_idx += 1
            elif line_num < 570:
                # 525 accounts get uncracked hashes (each unique)
                uncracked_idx = line_num - 45
                ntlm_hash = UNCRACKED_HASHES[uncracked_idx]
                lm_hash = BLANK_LM
            elif unique_hash_idx < len(unique_cracked_hashes):
                # Use remaining unique cracked hashes first (no reuse)
                ntlm_hash = unique_cracked_hashes[unique_hash_idx]
                unique_hash_idx += 1
                lm_hash = BLANK_LM
            else:
                # All unique hashes used, now use the 24 reused hashes
                # These are reused passwords #2-25
                reuse_idx = (line_num - 570 - len(unique_cracked_hashes) + 20) % 24
                ntlm_hash = reused_hashes[reuse_idx]
                lm_hash = BLANK_LM

            # Track stats
            stats["total_accounts"] += 1
            stats["by_domain"][domain]["total"] += 1

            if is_computer:
                stats["computer_accounts"] += 1
                stats["by_domain"][domain]["computer"] += 1
            else:
                stats["user_accounts"] += 1

            if use_dcsync:
                stats["dcsync_format"] += 1
                if is_enabled:
                    stats["enabled_accounts"] += 1
                    stats["by_domain"][domain]["enabled"] += 1
                else:
                    stats["disabled_accounts"] += 1
                    stats["by_domain"][domain]["disabled"] += 1
            else:
                stats["standard_format"] += 1

            if ntlm_hash == BLANK_NTLM:
                stats["blank_passwords"] += 1
                stats["by_domain"][domain]["blank"] += 1

            if lm_hash != BLANK_LM:
                stats["non_blank_lm_hashes"] += 1

            if ntlm_hash in CRACKED_HASHES:
                stats["cracked_accounts"] += 1
                stats["by_domain"][domain]["cracked"] += 1

                # Track password length
                pwd = CRACKED_HASHES[ntlm_hash]
                pwd_len = len(pwd)
                stats["password_lengths"][pwd_len] = stats["password_lengths"].get(pwd_len, 0) + 1
            else:
                stats["uncracked_accounts"] += 1

            # Track shared passwords
            stats["shared_passwords"][ntlm_hash] = stats["shared_passwords"].get(ntlm_hash, 0) + 1

            # Create the line
            if use_dcsync:
                status = "Enabled" if is_enabled else "Disabled"
                line = f"{full_username}:{line_num}:{lm_hash}:{ntlm_hash}::: (status={status})"
            else:
                line = f"{full_username}::{lm_hash}:{ntlm_hash}:::"

            accounts.append(line)
            line_num += 1

    # Calculate shared password stats
    shared_count = sum(1 for count in stats["shared_passwords"].values() if count > 1)
    unique_count = sum(1 for count in stats["shared_passwords"].values() if count == 1)
    max_shared = max(stats["shared_passwords"].values())

    # Write the file
    with open("/home/njoyzrd/projects/hm1k/testData/example_dcsync.txt", "w") as f:
        f.write("\n".join(accounts))
        f.write("\n")

    # Print comprehensive stats
    print("=" * 70)
    print("EXAMPLE_DCSYNC.TXT QA REFERENCE STATISTICS")
    print("=" * 70)
    print()
    print("OVERALL COUNTS:")
    print(f"  Total Accounts:           {stats['total_accounts']}")
    print(f"  User Accounts:            {stats['user_accounts']}")
    print(f"  Computer Accounts:        {stats['computer_accounts']} (ending with $)")
    print()
    print("ACCOUNT STATUS (dcsync format only):")
    print(f"  DCSynC Format Lines:      {stats['dcsync_format']}")
    print(f"  Standard Format Lines:    {stats['standard_format']}")
    print(f"  Enabled Accounts:         {stats['enabled_accounts']}")
    print(f"  Disabled Accounts:        {stats['disabled_accounts']}")
    print()
    print("PASSWORD ANALYSIS:")
    print(f"  Cracked Accounts:         {stats['cracked_accounts']}")
    print(f"  Uncracked Accounts:       {stats['uncracked_accounts']}")
    print(f"  Blank Passwords:          {stats['blank_passwords']}")
    print(f"  Non-blank LM Hashes:      {stats['non_blank_lm_hashes']}")
    print()
    print("SHARED PASSWORD ANALYSIS:")
    print(f"  Unique Passwords:         {unique_count}")
    print(f"  Shared Passwords:         {shared_count} (password used by >1 account)")
    print(f"  Max Accounts Sharing:     {max_shared}")

    # Show top shared passwords
    top_shared = sorted(stats["shared_passwords"].items(), key=lambda x: x[1], reverse=True)[:10]
    print()
    print("TOP 10 MOST SHARED PASSWORDS:")
    for hash_val, count in top_shared:
        if hash_val in CRACKED_HASHES:
            pwd = CRACKED_HASHES[hash_val]
            if pwd == "":
                pwd = "(blank)"
            print(f"  {count:3d} accounts: {pwd}")
        else:
            print(f"  {count:3d} accounts: (uncracked)")

    # Password length distribution
    print()
    print("PASSWORD LENGTH DISTRIBUTION (cracked only):")
    for length in sorted(stats["password_lengths"].keys()):
        count = stats["password_lengths"][length]
        print(f"  Length {length:2d}: {count:4d} accounts")

    # Domain breakdown
    print()
    print("BY DOMAIN:")
    for domain, domain_stats in stats["by_domain"].items():
        print(f"\n  {domain}:")
        print(f"    Total:     {domain_stats['total']}")
        print(f"    Enabled:   {domain_stats['enabled']}")
        print(f"    Disabled:  {domain_stats['disabled']}")
        print(f"    Computer:  {domain_stats['computer']}")
        print(f"    Cracked:   {domain_stats['cracked']}")
        print(f"    Blank:     {domain_stats['blank']}")

    print()
    print("=" * 70)
    print(f"File written to: testData/example_dcsync.txt")
    print("=" * 70)


if __name__ == "__main__":
    main()
