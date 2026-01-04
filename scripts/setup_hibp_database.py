#!/usr/bin/env python3
"""
HIBP Database Setup Script

This script handles the complete setup of the HIBP (Have I Been Pwned) database
for HashMaster1000. It can:

1. Download the complete HIBP NTLM database from the API (~70-80GB)
2. Convert an existing text file to SQLite for faster lookups
3. Check the status of existing databases

Usage:
    # Convert existing text file to SQLite
    python setup_hibp_database.py --convert /path/to/pwnedpasswords-ntlm.txt

    # Download and convert to SQLite (full setup)
    python setup_hibp_database.py --download --output-dir /path/to/data

    # Check status of databases
    python setup_hibp_database.py --status /path/to/database

    # Show help
    python setup_hibp_database.py --help
"""

import argparse
import logging
import os
import sys
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.hibp_downloader import (
    convert_text_to_sqlite,
    get_sqlite_db_info,
    SQLiteConversionState,
)
from app.hibp_checker import (
    validate_local_db_path,
    get_local_db_status,
    init_local_hibp_database,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def format_size(size_bytes: int) -> str:
    """Format bytes as human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_time(seconds: float) -> str:
    """Format seconds as human readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def progress_callback(state: SQLiteConversionState) -> None:
    """Print progress during conversion."""
    pct = state.progress_percentage
    processed = state.processed_lines
    total = state.total_lines
    elapsed = format_time(state.elapsed_seconds)

    # Estimate remaining time
    if pct > 0:
        total_time = state.elapsed_seconds / (pct / 100)
        remaining = total_time - state.elapsed_seconds
        remaining_str = format_time(remaining)
    else:
        remaining_str = "calculating..."

    print(f"\r  Progress: {pct:.1f}% ({processed:,}/{total:,} lines) - "
          f"Elapsed: {elapsed} - Remaining: {remaining_str}    ", end="", flush=True)


def cmd_convert(args: argparse.Namespace) -> int:
    """Convert a text file to SQLite database."""
    text_file = args.input_file

    if not os.path.exists(text_file):
        print(f"Error: Input file not found: {text_file}")
        return 1

    # Determine output path
    if args.output:
        db_path = args.output
    else:
        base_path = os.path.splitext(text_file)[0]
        db_path = base_path + ".db"

    # Check if output already exists
    if os.path.exists(db_path) and not args.force:
        print(f"Error: Output file already exists: {db_path}")
        print("Use --force to overwrite")
        return 1

    # Get input file info
    file_size = os.path.getsize(text_file)
    print(f"\nHIBP Text to SQLite Conversion")
    print(f"{'='*50}")
    print(f"Input file:  {text_file}")
    print(f"Input size:  {format_size(file_size)}")
    print(f"Output file: {db_path}")
    print()

    # Estimate time
    estimated_lines = file_size // 40
    print(f"Estimated entries: ~{estimated_lines:,}")
    print(f"Estimated time: {format_time(estimated_lines / 500000 * 60)}  (varies by disk speed)")
    print()

    if not args.yes:
        response = input("Continue? [y/N] ").strip().lower()
        if response != 'y':
            print("Aborted.")
            return 0

    print("\nStarting conversion...")
    print()

    # Run conversion
    start_time = time.time()
    success, message, result_path = convert_text_to_sqlite(
        text_file,
        db_path,
        batch_size=100000,
        progress_callback=progress_callback
    )

    print()  # New line after progress
    print()

    if success:
        elapsed = time.time() - start_time
        db_size = os.path.getsize(result_path) if result_path else 0

        print(f"Conversion complete!")
        print(f"{'='*50}")
        print(f"Output file: {result_path}")
        print(f"Output size: {format_size(db_size)}")
        print(f"Total time:  {format_time(elapsed)}")
        print()

        # Verify the database
        print("Verifying database...")
        db_info = get_sqlite_db_info(result_path)
        if db_info:
            print(f"  Hash count: {db_info['hash_count']:,}")
            print(f"  Sample hash: {db_info['sample_hash']}")
            print(f"  Valid: Yes")
        else:
            print("  Warning: Could not verify database")

        return 0
    else:
        print(f"Error: {message}")
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Check status of HIBP databases."""
    db_path = args.path

    print(f"\nHIBP Database Status")
    print(f"{'='*50}")
    print(f"Path: {db_path}")
    print()

    if not os.path.exists(db_path):
        print("Status: NOT FOUND")
        print()

        # Check for alternative paths
        alternatives = []
        if db_path.endswith('.txt'):
            sqlite_path = db_path[:-4] + '.db'
            if os.path.exists(sqlite_path):
                alternatives.append(sqlite_path)
        elif db_path.endswith('.db'):
            text_path = db_path[:-3] + '.txt'
            if os.path.exists(text_path):
                alternatives.append(text_path)

        if alternatives:
            print("Found alternative files:")
            for alt in alternatives:
                print(f"  - {alt}")

        return 1

    # Check if it's a SQLite database
    if db_path.endswith('.db'):
        db_info = get_sqlite_db_info(db_path)
        if db_info:
            print(f"Type: SQLite Database")
            print(f"Hash count: {db_info['hash_count']:,}")
            print(f"File size: {format_size(db_info['file_size_bytes'])}")
            print(f"File date: {db_info['file_date']}")
            print(f"Valid: Yes")
            print()
            print("This database is ready for use with HashMaster1000.")
            return 0
        else:
            print("Type: SQLite Database (INVALID)")
            print("The database file exists but is not a valid HIBP database.")
            return 1

    # Check if it's a text file
    is_valid, message, info = validate_local_db_path(db_path)

    if is_valid:
        print(f"Type: Text File (sorted)")
        print(f"Hash count: ~{info.get('estimated_entries', 0):,}")
        print(f"File size: {format_size(info.get('file_size_bytes', 0))}")
        print(f"Sorted: {info.get('is_sorted', False)}")
        print()
        print("This file can be used with HashMaster1000 (binary search mode).")
        print()

        # Suggest SQLite conversion
        sqlite_path = os.path.splitext(db_path)[0] + '.db'
        if os.path.exists(sqlite_path):
            print(f"SQLite version also available: {sqlite_path}")
        else:
            print("For better performance, consider converting to SQLite:")
            print(f"  python setup_hibp_database.py --convert {db_path}")

        return 0
    else:
        print(f"Type: Unknown")
        print(f"Error: {message}")
        if info:
            print(f"Details: {info}")
        return 1


def cmd_download(args: argparse.Namespace) -> int:
    """Download HIBP database from API."""
    print("\nHIBP Database Download")
    print(f"{'='*50}")
    print()
    print("This feature downloads the complete HIBP NTLM database from the API.")
    print("This will take several hours and download approximately 70-80GB of data.")
    print()
    print("For now, please use the HashMaster1000 web interface at:")
    print("  https://127.0.0.1:8443/hibp/download")
    print()
    print("Or download manually from:")
    print("  https://haveibeenpwned.com/Passwords")
    print()
    print("After downloading, convert to SQLite for better performance:")
    print("  python setup_hibp_database.py --convert /path/to/downloaded/file.txt")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HIBP Database Setup Tool for HashMaster1000",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert existing text file to SQLite (recommended)
  python setup_hibp_database.py --convert /path/to/pwnedpasswords-ntlm.txt

  # Check database status
  python setup_hibp_database.py --status /path/to/pwnedpasswords-ntlm.txt
  python setup_hibp_database.py --status /path/to/pwnedpasswords-ntlm.db

  # Convert with custom output path
  python setup_hibp_database.py --convert input.txt --output /data/hibp.db

  # Force overwrite existing database
  python setup_hibp_database.py --convert input.txt --force
        """
    )

    parser.add_argument(
        '--convert', '-c',
        metavar='INPUT_FILE',
        dest='input_file',
        help='Convert a text file to SQLite database'
    )

    parser.add_argument(
        '--status', '-s',
        metavar='PATH',
        dest='path',
        help='Check status of a database file'
    )

    parser.add_argument(
        '--download', '-d',
        action='store_true',
        help='Download HIBP database from API (not yet implemented)'
    )

    parser.add_argument(
        '--output', '-o',
        metavar='PATH',
        help='Output path for SQLite database (default: same as input with .db extension)'
    )

    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force overwrite if output file exists'
    )

    parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Skip confirmation prompts'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine which command to run
    if args.input_file:
        return cmd_convert(args)
    elif args.path:
        return cmd_status(args)
    elif args.download:
        return cmd_download(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
