import json
import argparse
import binascii
import logging
from typing import Union, Any, Optional
import password_analysis_tools  # Local import: password_analysis.tools.py in project folder

# Configure logging
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s"
)

error_report = []


# Helper function to properly pass boolean values from flask to argparse
def str2bool(value: str) -> bool:
    return value.lower() in ("true", "1", "yes")


def process_files(
    pwdump_file: str, potfile: str
) -> dict[str, dict[str, Optional[str]]]:
    logging.info(f"Processing {pwdump_file} (pwdump_file) and {potfile} (potfile)")
    total_accounts, valid_accounts = 0, 0  # Initialize row counters
    account_data = {}

    try:
        # Read pwdump data into a dictionary to prepare for analysis
        pwdump_data = {}
        with open(pwdump_file, "r") as f:
            for line in f:
                total_accounts += 1
                parts = line.strip().split(":")
                if len(parts) == 7:
                    valid_accounts += 1
                    # Storing first, third, and fourth elements in a dictionary for each account
                    pwdump_data[parts[0]] = {"lm_hash": parts[2], "ntlm_hash": parts[3]}
                else:
                    logging.warning(
                        f"Skipping corrupt pwdump file line: {line.strip()}"
                    )
                    error_report.append(f"Invalid line format: {line.strip()}")

        logging.info(
            f"Source pwdump file contains {total_accounts} entries with {valid_accounts} valid accounts"
        )

        # Read potfile data into dictionary to prepare for analysis
        cracked_hashes = {}
        cracked_hashes["31d6cfe0d16ae931b73c59d7e0c089c0"] = (
            ""  # Add blank password hash to dictionary
        )
        with open(potfile, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) != 2:
                    logging.warning(f"Skipping corrupt potfile line: {line.strip()}")
                    error_report.append(f"Invalid line format: {line.strip()}")
                    continue

                # Only if the line is properly split, assign to variables
                ntlm_hash, password = parts
                cracked_hashes[ntlm_hash] = password

        logging.info(f"Total entries in potfile: {len(cracked_hashes)}")

        if len(cracked_hashes) > valid_accounts:
            logging.warning(
                "There are more cracked passwords in the potfile than accounts being cracked!"
            )
            error_report.append(
                "Warning: More cracked passwords in potfile than accounts in pwdump!"
            )

        for account_name, data in pwdump_data.items():
            # Default values for locked, disabled, and last_pw_change
            account_entry = {
                "lm_hash": data.get("lm_hash"),
                "ntlm_hash": data.get("ntlm_hash"),
                "cracked_pw": None,  # Default to None if not found
                "locked": None,  # Placeholder for future data
                "disabled": None,  # Placeholder for future data
                "last_pw_change": None,  # Placeholder for future data
            }

            # Check if the NTLM hash exists in potfile and retrieve the cracked password if available
            if account_entry["ntlm_hash"] in cracked_hashes:
                cracked_value = cracked_hashes[account_entry["ntlm_hash"]]

                # Check if the cracked value is in the $HEX[...] format
                if cracked_value.startswith("$HEX[") and cracked_value.endswith("]"):
                    # Extract the hex-encoded string and decode it
                    hex_string = cracked_value[5:-1]  # Remove $HEX[ and ]
                    try:
                        decoded_value = binascii.unhexlify(hex_string).decode("utf-8")
                        account_entry["cracked_pw"] = decoded_value
                        logging.info(
                            f'HEX decoded for password: {account_entry["cracked_pw"]}'
                        )
                    except (binascii.Error, UnicodeDecodeError):
                        # Handle decoding errors if the value is not valid hex or UTF-8
                        account_entry["cracked_pw"] = cracked_value
                        logging.warning(
                            f'HEX decoding failed for password: {account_entry["cracked_pw"]}'
                        )
                else:
                    # Use the value as-is if it's not hex-encoded
                    account_entry["cracked_pw"] = cracked_value

            # Add to account dictionary with account name as the top-level key
            account_data[account_name] = account_entry

    except IOError as e:
        logging.error(f"File operation error: {e}")
        error_report.append(f"File operation error: {e}")

    # Return the populated account_data dictionary
    return account_data


# Function to extract a list of passwords
def load_passwords(file_path: str) -> list[str]:
    try:
        with open(file_path, "r") as file:
            passwords = [
                line.strip() for line in file if line.strip()
            ]  # Ignore empty lines
        logging.info(f"Loaded {len(passwords)} passwords from {file_path}")
        return passwords
    except IOError as e:
        logging.error(f"Failed to read {file_path}: {e}")
        return []


# Convert to an ordered array format for display by chart.js
def cracking_stats_array(stats: dict[str, Any]) -> list[dict[str, Union[str, int]]]:
    # Define the desired key order
    key_order = [
        "Cracked Accounts: ",
        "Uncracked Accounts: ",
        "Total Accounts Analyzed: ",
        "Percent of Accounts Cracked: ",
        "Cracked NTLM Hashes: ",
        "Uncracked NTLM Hashes: ",
        "Unique NTLM Hashes Analyzed: ",
        "Percent of NTLM Hashes Cracked: ",
        "Total LANMan Hashes: ",
        "Shortest Cracked Password: ",
        "Longest Cracked Password: ",
        "Average Password Length: ",
    ]
    ordered_data = [{"key": key, "value": stats[key]} for key in key_order]
    return ordered_data


def main(args):
    # Check input files for errors and prepare data for analysis
    account_data = process_files(args.pwdump_file, args.potfile)

    # Call the crack_stats function to prepare data for the Cracking Stats report table
    stats_report = password_analysis_tools.crack_stats(
        account_data,
        args.policy_min_pw_len,
        args.policy_complexity_req,
        ignore_blank_passwords=args.ignore_blank_passwords,
    )

    # Convert the returned stats_report to an array to ensure chart.js orders properly
    stats_table = cracking_stats_array(stats_report["cracking_stats"])

    # Create a list of all cracked passwords from the job (including duplicates)
    cracked_passwords = [
        account["cracked_pw"]
        for account in account_data.values()
        if account.get("cracked_pw")
    ]

    # Call the substring_analysis function to return Top Substrings for the report
    substrings = password_analysis_tools.substring_analysis(
        cracked_passwords,
        args.substring_min_len,
        args.substring_max_len,
        args.substring_freq_threshold,
        args.substring_normalize,
        args.substring_disp_nest,
    )

    # Call the dictionary_analysis fuction to return (English) Dictionary Words for the report
    detailed_results, english_words = password_analysis_tools.dictionary_analysis(
        cracked_passwords, args.dictionary_min_len, args.dictionary_disp_nest
    )

    # Call the check_pw_reuse fuction to return Password Reuse data for the report
    pw_reuse_table = password_analysis_tools.check_pw_reuse(args.pwdump_file)

    # Prepare Fails Password Policy - Min Length Report
    fail_min_length = stats_report["pw_fails_min_length"]

    # Prepare Fails Password Policy - Complexity Report
    fail_complexity = stats_report["pw_fails_complexity"]

    # Prepare Fails Password Policy - Blank Password
    fail_blank = stats_report["pw_fails_blank"]

    # Prepare Fails Password Policy - Max Age Report
    fail_max_age = stats_report["pw_fails_max_age"]

    # Write the necessary report data to JSON files stored in the data/ folder
    with open("data/cracking_stats_table.json", "w") as f:
        json.dump(stats_table, f, indent=4)
    with open("data/pw_account_pie.json", "w") as f:
        json.dump(stats_report["pw_account_pie"], f)
    with open("data/pw_ntlm_hash_pie.json", "w") as f:
        json.dump(stats_report["pw_ntlm_hash_pie"], f)
    with open("data/pw_length_distribution.json", "w") as f:
        json.dump(stats_report["pw_length_distribution"], f)
    with open("data/pw_top_passwords.json", "w") as f:
        json.dump(stats_report["pw_top_passwords"], f)
    with open("data/pw_substrings.json", "w") as f:
        json.dump(substrings, f, indent=4)
    with open("data/pw_dict_words.json", "w") as f:
        json.dump(english_words, f, indent=4)
    with open("data/pw_reuse_table.json", "w") as f:
        json.dump(pw_reuse_table, f)
    with open("data/pw_fails_min_length.json", "w") as f:
        json.dump(fail_min_length, f)
    with open("data/pw_fails_complexity.json", "w") as f:
        json.dump(fail_complexity, f)
    with open("data/pw_fails_blank.json", "w") as f:
        json.dump(fail_blank, f)
    with open("data/pw_fails_max_age.json", "w") as f:
        json.dump(fail_max_age, f)

    # Dump raw account, hash and password data
    with open("data/account_data.json", "w") as f:
        json.dump(account_data, f)

    # Print and save any errors produced during runtime
    print(f"\nError Report:\n{error_report}")
    with open("data/error_report.txt", "w") as f:
        for item in error_report:
            f.write(str(item) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process password cracking data")
    parser.add_argument("pwdump_file", help="Path to pwdump file")
    parser.add_argument("potfile", help="Path to potfile")
    parser.add_argument(
        "--policy_min_pw_len", type=int, default=8, help="Min Password Length"
    )
    parser.add_argument(
        "--policy_max_pw_age", type=int, default=90, help="Max Password Age"
    )
    parser.add_argument(
        "--policy_complexity_req",
        type=int,
        default=3,
        help="Complexity Categories Required",
    )
    parser.add_argument(
        "--substring_min_len", type=int, default=2, help="Minimum Substring Length"
    )
    parser.add_argument(
        "--substring_max_len", type=int, default=20, help="Maximum Substring Length"
    )
    parser.add_argument(
        "--substring_freq_threshold",
        type=int,
        default=2,
        help="Frequency Threshold for Substrings",
    )
    parser.add_argument(
        "--substring_disp_nest",
        type=str2bool,
        default=False,
        help="Display Nested Substrings",
    )
    parser.add_argument(
        "--substring_normalize",
        type=str2bool,
        default=False,
        help="Analyze Substrings in Lowercase",
    )
    parser.add_argument(
        "--dictionary_min_len",
        type=int,
        default=4,
        help="Minimum Dictionary Word Length",
    )
    parser.add_argument(
        "--dictionary_disp_nest",
        type=str2bool,
        default=False,
        help="Display Nested Dictionary Words",
    )
    parser.add_argument(
        "--ignore_blank_passwords",
        type=str2bool,
        default=False,
        help="Ignore Blank Passwords",
    )

    args = parser.parse_args()
    print("\nStep 2: ")
    print(f"HashMaster1000.py arguments parsed:\nargs={args}\n")
    main(args)
