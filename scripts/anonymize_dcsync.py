#!/usr/bin/env python3
"""
Anonymize DCSync files for sharing or testing purposes.

This script transforms a dcsync file by:
- Changing the domain to example.com
- Replacing usernames with random First.Last format names
- Keeping the RID, LM hash, and NTLM hash unchanged
- Removing the (status=Enabled/Disabled) suffix

Usage:
    python anonymize_dcsync.py <input_file> <output_file>

Example:
    python anonymize_dcsync.py original_dump.txt anonymized_dump.txt
"""

import argparse
import random
import re
import sys

# Common first names
FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph",
    "Thomas", "Charles", "Christopher", "Daniel", "Matthew", "Anthony", "Mark",
    "Donald", "Steven", "Paul", "Andrew", "Joshua", "Kenneth", "Kevin", "Brian",
    "George", "Timothy", "Ronald", "Edward", "Jason", "Jeffrey", "Ryan",
    "Jacob", "Gary", "Nicholas", "Eric", "Jonathan", "Stephen", "Larry",
    "Justin", "Scott", "Brandon", "Benjamin", "Samuel", "Raymond", "Gregory",
    "Frank", "Alexander", "Patrick", "Jack", "Dennis", "Jerry", "Tyler",
    "Aaron", "Jose", "Adam", "Nathan", "Henry", "Douglas", "Zachary", "Peter",
    "Mary", "Patricia", "Jennifer", "Linda", "Barbara", "Elizabeth", "Susan",
    "Jessica", "Sarah", "Karen", "Lisa", "Nancy", "Betty", "Margaret", "Sandra",
    "Ashley", "Kimberly", "Emily", "Donna", "Michelle", "Dorothy", "Carol",
    "Amanda", "Melissa", "Deborah", "Stephanie", "Rebecca", "Sharon", "Laura",
    "Cynthia", "Kathleen", "Amy", "Angela", "Shirley", "Anna", "Brenda",
    "Pamela", "Emma", "Nicole", "Helen", "Samantha", "Katherine", "Christine",
    "Debra", "Rachel", "Carolyn", "Janet", "Catherine", "Maria", "Heather",
    "Diane", "Ruth", "Julie", "Olivia", "Joyce", "Virginia", "Victoria"
]

# Common last names
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzales", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen",
    "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera",
    "Campbell", "Mitchell", "Carter", "Roberts", "Gomez", "Phillips", "Evans",
    "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart",
    "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz",
    "Morgan", "Cooper", "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos",
    "Kim", "Cox", "Ward", "Richardson", "Watson", "Brooks", "Chavez", "Wood",
    "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes", "Price", "Alvarez",
    "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez"
]


def generate_random_name(used_names: set) -> str:
    """Generate a unique random First.Last name."""
    max_attempts = 1000
    for _ in range(max_attempts):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        name = f"{first}.{last}"
        if name not in used_names:
            used_names.add(name)
            return name

    # If we exhaust common names, add a number suffix
    counter = 1
    while True:
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        name = f"{first}.{last}{counter}"
        if name not in used_names:
            used_names.add(name)
            return name
        counter += 1


def anonymize_line(line: str, username_map: dict, used_names: set) -> str:
    """
    Anonymize a single dcsync line.

    Input format:  DOMAIN\\username:RID:LM_HASH:NTLM_HASH::: (status=Enabled)
    Output format: example.com\\First.Last:RID:LM_HASH:NTLM_HASH:::
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return line

    # Remove the status suffix (e.g., " (status=Enabled)" or " (status=Disabled)")
    status_pattern = r'\s*\(status=\w+\)\s*$'
    line = re.sub(status_pattern, '', line)

    # Parse the line: DOMAIN\username:RID:LM:NTLM:::
    # Handle both backslash formats
    match = re.match(r'^([^\\]+)\\([^:]+):(.*)$', line)

    if not match:
        # Try without domain prefix (standard pwdump format)
        match = re.match(r'^([^:]+):(.*)$', line)
        if match:
            original_username = match.group(1)
            rest_of_line = match.group(2)

            # Check if this is a machine account (ends with $)
            if original_username.endswith('$'):
                # Keep machine account format but anonymize
                if original_username not in username_map:
                    machine_num = len([k for k in username_map.keys() if k.endswith('$')])
                    username_map[original_username] = f"WORKSTATION{machine_num:04d}$"
                new_username = username_map[original_username]
            else:
                if original_username not in username_map:
                    username_map[original_username] = generate_random_name(used_names)
                new_username = username_map[original_username]

            return f"example.com\\{new_username}:{rest_of_line}"
        else:
            # Can't parse, return as-is
            return line

    original_domain = match.group(1)
    original_username = match.group(2)
    rest_of_line = match.group(3)

    # Check if this is a machine account (ends with $)
    if original_username.endswith('$'):
        # Keep machine account format but anonymize
        if original_username not in username_map:
            machine_num = len([k for k in username_map.keys() if k.endswith('$')])
            username_map[original_username] = f"WORKSTATION{machine_num:04d}$"
        new_username = username_map[original_username]
    else:
        # Regular user account - generate random name
        if original_username not in username_map:
            username_map[original_username] = generate_random_name(used_names)
        new_username = username_map[original_username]

    return f"example.com\\{new_username}:{rest_of_line}"


def anonymize_dcsync_file(input_file: str, output_file: str) -> None:
    """Anonymize an entire dcsync file."""
    username_map = {}  # Maps original usernames to anonymized names
    used_names = set()  # Track used names to avoid duplicates

    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            lines = infile.readlines()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    anonymized_lines = []
    for line in lines:
        anonymized_line = anonymize_line(line, username_map, used_names)
        anonymized_lines.append(anonymized_line)

    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.write('\n'.join(anonymized_lines))
            if anonymized_lines and not anonymized_lines[-1].endswith('\n'):
                outfile.write('\n')
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

    print(f"Successfully anonymized {len(lines)} lines.")
    print(f"  - {len(username_map)} unique accounts processed")
    print(f"  - Output written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Anonymize a dcsync file for sharing or testing purposes.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python anonymize_dcsync.py dump.txt anonymized_dump.txt
    python anonymize_dcsync.py /path/to/input.ntds /path/to/output.txt

The script will:
    - Change the domain to 'example.com'
    - Replace usernames with random First.Last names
    - Keep machine accounts as WORKSTATION####$
    - Preserve RID, LM hash, and NTLM hash values
    - Remove the (status=Enabled/Disabled) suffix
        """
    )
    parser.add_argument('input_file', help='Path to the input dcsync file')
    parser.add_argument('output_file', help='Path for the anonymized output file')

    args = parser.parse_args()

    anonymize_dcsync_file(args.input_file, args.output_file)


if __name__ == '__main__':
    main()
