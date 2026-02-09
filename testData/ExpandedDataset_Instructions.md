# HM1K Sample Dataset (Expanded) - Expected Results

This dataset expands the original sample to provide more cracked password variety for:
- Dictionary word analysis
- Substring analysis
- Password reuse analysis

## Files

- `example_ADD_large.json`
- `example_large.potfile`

## Dataset size

- Domain Users: 5095
- Computer Accounts: 5095
- Total Accounts: 10190

## Crack statistics (expected)

Blank NTLM hash (blank password):
`31d6cfe0d16ae931b73c59d7e0c089c0`

Hash Master 1000 treats blank passwords as cracked *accounts*, but excludes the blank hash from unique-hash crack metrics.

Expected values:
- Unique NTLM hashes (including blank): 9777
- Unique NTLM hashes (excluding blank): 9776
- Cracked unique NTLM hashes (excluding blank): 1533
- Cracked accounts (includes blank-password accounts): 1898
  - Cracked user accounts: 1897
  - Cracked computer accounts: 1
  - Blank-password accounts: 31

Approx crack rates:
- Hash crack rate (unique hashes, excluding blank): 15.7%
- Account crack rate (accounts): 18.6%

## Expected “top” dictionary words (rough)

Exact ordering can vary based on exclusions, but you should see many of these near the top:

- `fall`: appears in ~67 cracked passwords
- `mar`: appears in ~65 cracked passwords
- `password`: appears in ~65 cracked passwords
- `summer`: appears in ~64 cracked passwords
- `winter`: appears in ~61 cracked passwords
- `spring`: appears in ~60 cracked passwords
- `sales`: appears in ~51 cracked passwords
- `hr`: appears in ~48 cracked passwords
- `laptop`: appears in ~48 cracked passwords
- `office`: appears in ~45 cracked passwords
- `azure`: appears in ~44 cracked passwords
- `finance`: appears in ~43 cracked passwords

## Expected “top” substrings (seeded)

- `2026`: appears in ~218 cracked passwords
- `2025`: appears in ~180 cracked passwords
- `2024`: appears in ~168 cracked passwords
- `fall`: appears in ~67 cracked passwords
- `password`: appears in ~65 cracked passwords
- `summer`: appears in ~64 cracked passwords
- `winter`: appears in ~61 cracked passwords
- `spring`: appears in ~60 cracked passwords
- `admin`: appears in ~42 cracked passwords
- `welcome`: appears in ~38 cracked passwords
- `testcorp`: appears in ~32 cracked passwords

## Notes

- Privileged accounts were kept as-is, the expansion focuses on normal user accounts for password variety.
- New computer accounts were generated as uncracked to avoid skewing results.
- The potfile is sorted by hash for stable diffs and repeatable tests.
