#!/usr/bin/env python3
"""
Update metadata for imported rule files.
Run on the server: python3 scripts/update_rule_metadata.py
"""

import json
import re
from pathlib import Path

# Rule metadata definitions based on research from hashcat community
RULE_METADATA = {
    "best64.rule": {
        "name": "Best64",
        "description": "Top 64 performing rules, optimized for quick cracking. Great standalone or stacked with other rules.",
        "tags": ["popular", "fast", "essential", "hashcat-builtin"]
    },
    "combinator.rule": {
        "name": "Combinator",
        "description": "Rules for combining and mutating wordlist entries in various ways.",
        "tags": ["combination", "hashcat-builtin"]
    },
    "d3ad0ne.rule": {
        "name": "d3ad0ne",
        "description": "Classic ruleset by d3ad0ne with ~30k rules. Legacy ruleset with historical significance in password cracking.",
        "tags": ["large", "legacy", "comprehensive", "hashcat-builtin"]
    },
    "dive.rule": {
        "name": "Dive",
        "description": "Large comprehensive ruleset (~99k rules) sorted by popularity. Thorough with great success rate. Best with fast hashes (NT, MD5) or short wordlists.",
        "tags": ["large", "comprehensive", "thorough", "slow", "hashcat-builtin"]
    },
    "generated.rule": {
        "name": "Generated",
        "description": "Auto-generated rules through hashcat testing and analysis.",
        "tags": ["generated", "hashcat-builtin"]
    },
    "generated2.rule": {
        "name": "Generated 2",
        "description": "Second set of auto-generated rules through hashcat testing. About 30k rules with good results.",
        "tags": ["generated", "large", "hashcat-builtin"]
    },
    "Incisive-leetspeak.rule": {
        "name": "Incisive Leetspeak",
        "description": "Advanced leetspeak transformations with comprehensive character substitutions.",
        "tags": ["leetspeak", "substitution"]
    },
    "InsidePro-HashManager.rule": {
        "name": "InsidePro HashManager",
        "description": "6,551 rules from InsidePro HashManager. Great paired with best64. Produces good results without being too large.",
        "tags": ["medium", "insidepro", "effective", "hashcat-builtin"]
    },
    "InsidePro-PasswordsPro.rule": {
        "name": "InsidePro PasswordsPro",
        "description": "3,234 rules from InsidePro PasswordsPro v2.5.5.0. Good results and easily combinable with other rules.",
        "tags": ["medium", "insidepro", "effective", "hashcat-builtin"]
    },
    "leetspeak.rule": {
        "name": "Leetspeak",
        "description": "Basic leetspeak character substitutions (a→4, e→3, i→1, o→0, s→5, etc.).",
        "tags": ["leetspeak", "substitution", "hashcat-builtin"]
    },
    "OneRuleToRuleThemAll.rule": {
        "name": "OneRuleToRuleThemAll",
        "description": "~50k rules from NotSoSecure. Meta-analysis of top 25% performing rules from best64, T0XlC, dive, d3ad0ne, and more. Cracked 68.36% of 4.3M test hashes.",
        "tags": ["popular", "comprehensive", "effective", "notsosecure"]
    },
    "OneRuleToRuleThemStill.rule": {
        "name": "OneRuleToRuleThemStill",
        "description": "Updated and optimized version of OneRuleToRuleThemAll with improved rule selection.",
        "tags": ["popular", "comprehensive", "effective", "optimized"]
    },
    "oscommerce.rule": {
        "name": "osCommerce",
        "description": "Rules specific to osCommerce password patterns and common mutations.",
        "tags": ["specific", "ecommerce", "hashcat-builtin"]
    },
    "quick.rule": {
        "name": "Quick",
        "description": "Small, fast ruleset for rapid password cracking attempts.",
        "tags": ["fast", "small", "quick"]
    },
    "rockyou-30000.rule": {
        "name": "RockYou 30000",
        "description": "Top 30,000 rules derived from analyzing the RockYou breach. Great balance of speed and effectiveness.",
        "tags": ["large", "rockyou", "effective", "hashcat-builtin"]
    },
    "specific.rule": {
        "name": "Specific",
        "description": "Targeted mutations for specific password patterns and conventions.",
        "tags": ["specific", "targeted", "hashcat-builtin"]
    },
    "T0XlC.rule": {
        "name": "T0XlC",
        "description": "4,085 tested rules by T0XlC. Great standalone ruleset compiled through testing.",
        "tags": ["t0xlc", "tested", "medium", "hashcat-builtin"]
    },
    "T0XlCv2.rule": {
        "name": "T0XlC v2",
        "description": "20,000 rules - expanded version of T0XlC rules from different testing runs.",
        "tags": ["t0xlc", "large", "comprehensive"]
    },
    "T0XlC_3_rule.rule": {
        "name": "T0XlC 3",
        "description": "Compact 30-rule subset of T0XlC rules for fast attacks.",
        "tags": ["t0xlc", "small", "fast"]
    },
    "T0XlC-insert_00-99_1950-2050_toprules_0_F.rule": {
        "name": "T0XlC Insert Years/Numbers",
        "description": "4,016 rules that insert common numbers (00-99) and years (1950-2050) at various positions.",
        "tags": ["t0xlc", "insert", "numbers", "years"]
    },
    "T0XlC-insert_space_and_special_0_F.rule": {
        "name": "T0XlC Insert Space/Special",
        "description": "480 rules that insert spaces and special characters at various positions.",
        "tags": ["t0xlc", "insert", "special-chars", "small"]
    },
    "T0XlC-insert_top_100_passwords_1_G.rule": {
        "name": "T0XlC Insert Top 100 Passwords",
        "description": "1,601 rules that insert fragments of top 100 common passwords.",
        "tags": ["t0xlc", "insert", "passwords"]
    },
    "T0XlC_insert_HTML_entities_0_Z.rule": {
        "name": "T0XlC Insert HTML Entities",
        "description": "6,662 rules that insert HTML entities and special sequences.",
        "tags": ["t0xlc", "insert", "html", "large"]
    },
    "toggles1.rule": {
        "name": "Toggles 1",
        "description": "Toggle character case at position 1. Simple and fast.",
        "tags": ["toggle", "case", "fast", "hashcat-builtin"]
    },
    "toggles2.rule": {
        "name": "Toggles 2",
        "description": "Toggle character case at positions 1-2. Good with best64.",
        "tags": ["toggle", "case", "fast", "hashcat-builtin"]
    },
    "toggles3.rule": {
        "name": "Toggles 3",
        "description": "Toggle character case at positions 1-3.",
        "tags": ["toggle", "case", "hashcat-builtin"]
    },
    "toggles4.rule": {
        "name": "Toggles 4",
        "description": "Toggle character case at positions 1-4.",
        "tags": ["toggle", "case", "hashcat-builtin"]
    },
    "toggles5.rule": {
        "name": "Toggles 5",
        "description": "Toggle character case at positions 1-5. More comprehensive but slower.",
        "tags": ["toggle", "case", "hashcat-builtin"]
    },
    "toggles-lm-ntlm.rule": {
        "name": "Toggles LM/NTLM",
        "description": "Toggle rules optimized for LM and NTLM hash cracking patterns.",
        "tags": ["toggle", "case", "ntlm", "lm", "windows"]
    },
    "unix-ninja-leetspeak.rule": {
        "name": "Unix-Ninja Leetspeak",
        "description": "Comprehensive leetspeak rules by unix-ninja with extensive character substitutions.",
        "tags": ["leetspeak", "substitution", "unix-ninja", "hashcat-builtin"]
    },
}


def update_metadata(index_path: str) -> None:
    """Update rule metadata in the index file."""
    index_path = Path(index_path)

    if not index_path.exists():
        print(f"Index file not found: {index_path}")
        return

    with open(index_path, "r") as f:
        data = json.load(f)

    updated_count = 0
    for resource in data.get("resources", []):
        if resource.get("resource_type") != "rules":
            continue

        filename = resource.get("name", "")

        # Check for exact match first
        if filename in RULE_METADATA:
            meta = RULE_METADATA[filename]
            resource["name"] = meta["name"]
            resource["description"] = meta["description"]
            # Merge tags, keeping "imported" if present
            existing_tags = set(resource.get("tags", []))
            new_tags = set(meta["tags"])
            resource["tags"] = sorted(existing_tags | new_tags)
            updated_count += 1
            print(f"Updated: {filename} -> {meta['name']}")
        else:
            # Try partial matches for variations
            for pattern, meta in RULE_METADATA.items():
                if pattern.lower() in filename.lower():
                    resource["name"] = meta["name"]
                    resource["description"] = meta["description"]
                    existing_tags = set(resource.get("tags", []))
                    new_tags = set(meta["tags"])
                    resource["tags"] = sorted(existing_tags | new_tags)
                    updated_count += 1
                    print(f"Updated (partial match): {filename} -> {meta['name']}")
                    break

    # Save updated index
    with open(index_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nUpdated {updated_count} rule file(s)")


if __name__ == "__main__":
    import sys

    # Default path
    index_path = "/opt/hm1k/data/agents/resources/index.json"

    if len(sys.argv) > 1:
        index_path = sys.argv[1]

    update_metadata(index_path)
