#!/usr/bin/env python3
"""
Benchmark script to compare HIBP lookup strategies.

This tests:
1. Binary search with persistent file handle (current small-batch approach)
2. Streaming merge-join (current large-batch approach)
3. Optimized approaches we can try

Run with:
    python benchmark_hibp.py /path/to/hibp.txt [hash_count]
"""

import argparse
import os
import random
import time
from typing import Callable

# Configure paths
DEFAULT_HIBP_PATH = "/mnt/d/pwnedpasswords_ntlm_2025.txt"


def get_sample_hashes(hibp_path: str, count: int) -> list[str]:
    """Extract random sample hashes from the HIBP file for testing."""
    print(f"Sampling {count} hashes from HIBP file...")

    file_size = os.path.getsize(hibp_path)
    hashes = set()

    with open(hibp_path, 'rb') as f:
        attempts = 0
        max_attempts = count * 10

        while len(hashes) < count and attempts < max_attempts:
            # Random position in file
            pos = random.randint(0, file_size - 100)
            f.seek(pos)
            f.readline()  # Skip partial line
            line = f.readline()

            if line:
                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if ':' in line_str:
                        hash_val = line_str.split(':')[0].upper()
                        if len(hash_val) == 32:
                            hashes.add(hash_val)
                except:
                    pass

            attempts += 1

    result = sorted(list(hashes))
    print(f"  Sampled {len(result)} unique hashes")
    return result


def benchmark_binary_search(
    hibp_path: str,
    hashes: list[str],
    file_size: int
) -> tuple[float, int]:
    """Benchmark binary search with persistent handle."""
    found = 0

    start = time.perf_counter()

    with open(hibp_path, 'rb') as f:
        for target_hash in hashes:
            low = 0
            high = file_size
            target_hash = target_hash.upper()

            while low < high:
                mid = (low + high) // 2
                f.seek(mid)

                if mid > 0:
                    f.readline()

                line = f.readline()
                if not line:
                    high = mid
                    continue

                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if ':' not in line_str:
                        high = mid
                        continue

                    current_hash = line_str.split(':')[0].upper()

                    if current_hash == target_hash:
                        found += 1
                        break
                    elif current_hash < target_hash:
                        low = f.tell()
                    else:
                        high = mid
                except:
                    high = mid

    elapsed = time.perf_counter() - start
    return elapsed, found


def benchmark_streaming_merge_join(
    hibp_path: str,
    sorted_hashes: list[str]
) -> tuple[float, int]:
    """Benchmark streaming merge-join (current implementation)."""
    found = 0
    target_idx = 0
    total = len(sorted_hashes)
    lines_read = 0

    start = time.perf_counter()

    with open(hibp_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            lines_read += 1

            if target_idx >= total:
                break

            line = line.strip()
            if not line or ':' not in line:
                continue

            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            hibp_hash = parts[0].upper()

            while target_idx < total and sorted_hashes[target_idx] < hibp_hash:
                target_idx += 1

            if target_idx < total and sorted_hashes[target_idx] == hibp_hash:
                found += 1
                target_idx += 1

            # Progress every 100M lines
            if lines_read % 100_000_000 == 0:
                elapsed = time.perf_counter() - start
                print(f"    {lines_read/1e9:.2f}B lines, {target_idx}/{total} targets, {elapsed:.1f}s")

    elapsed = time.perf_counter() - start
    return elapsed, found


def benchmark_streaming_binary(
    hibp_path: str,
    sorted_hashes: list[str]
) -> tuple[float, int]:
    """Benchmark streaming in binary mode (faster I/O)."""
    found = 0
    target_idx = 0
    total = len(sorted_hashes)

    start = time.perf_counter()

    with open(hibp_path, 'rb') as f:
        for line in f:
            if target_idx >= total:
                break

            # Fast parsing in binary
            try:
                colon_pos = line.find(b':')
                if colon_pos != 32:  # NTLM hash is 32 chars
                    continue

                hibp_hash = line[:32].decode('ascii').upper()
            except:
                continue

            while target_idx < total and sorted_hashes[target_idx] < hibp_hash:
                target_idx += 1

            if target_idx < total and sorted_hashes[target_idx] == hibp_hash:
                found += 1
                target_idx += 1

    elapsed = time.perf_counter() - start
    return elapsed, found


def benchmark_streaming_mmap(
    hibp_path: str,
    sorted_hashes: list[str]
) -> tuple[float, int]:
    """Benchmark streaming with mmap for faster I/O."""
    import mmap

    found = 0
    target_idx = 0
    total = len(sorted_hashes)

    file_size = os.path.getsize(hibp_path)

    start = time.perf_counter()

    with open(hibp_path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        pos = 0
        while pos < file_size and target_idx < total:
            # Find end of line
            newline_pos = mm.find(b'\n', pos)
            if newline_pos == -1:
                newline_pos = file_size

            line = mm[pos:newline_pos]
            pos = newline_pos + 1

            # Fast parsing
            if len(line) < 33:  # At least "HASH:"
                continue

            if line[32:33] != b':':
                continue

            try:
                hibp_hash = line[:32].decode('ascii').upper()
            except:
                continue

            while target_idx < total and sorted_hashes[target_idx] < hibp_hash:
                target_idx += 1

            if target_idx < total and sorted_hashes[target_idx] == hibp_hash:
                found += 1
                target_idx += 1

        mm.close()

    elapsed = time.perf_counter() - start
    return elapsed, found


def benchmark_early_exit_binary_search(
    hibp_path: str,
    sorted_hashes: list[str],
    file_size: int
) -> tuple[float, int]:
    """
    Binary search with early termination.

    Key insight: If we search for hashes in sorted order, after finding
    one hash, the next hash MUST be after it in the file. We can use
    the found position as the new 'low' bound.
    """
    found = 0

    start = time.perf_counter()

    with open(hibp_path, 'rb') as f:
        low = 0  # Persistent low bound that advances

        for target_hash in sorted_hashes:
            high = file_size
            target_hash = target_hash.upper()
            found_this = False

            while low < high:
                mid = (low + high) // 2
                f.seek(mid)

                if mid > 0:
                    f.readline()

                line = f.readline()
                if not line:
                    high = mid
                    continue

                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if ':' not in line_str:
                        high = mid
                        continue

                    current_hash = line_str.split(':')[0].upper()

                    if current_hash == target_hash:
                        found += 1
                        found_this = True
                        low = f.tell()  # Next hash must be after this
                        break
                    elif current_hash < target_hash:
                        low = f.tell()
                    else:
                        high = mid
                except:
                    high = mid

            if not found_this:
                # If not found, next hash still starts from current low
                pass

    elapsed = time.perf_counter() - start
    return elapsed, found


def estimate_time(elapsed: float, tested: int, total: int) -> str:
    """Estimate total time based on sample."""
    if tested == 0:
        return "N/A"
    per_hash = elapsed / tested
    total_estimate = per_hash * total

    if total_estimate < 60:
        return f"{total_estimate:.1f}s"
    elif total_estimate < 3600:
        return f"{total_estimate/60:.1f}min"
    else:
        return f"{total_estimate/3600:.1f}hr"


def main():
    parser = argparse.ArgumentParser(description="Benchmark HIBP lookup strategies")
    parser.add_argument("hibp_path", nargs="?", default=DEFAULT_HIBP_PATH,
                        help="Path to HIBP database file")
    parser.add_argument("--count", type=int, default=1000,
                        help="Number of hashes to test (default: 1000)")
    parser.add_argument("--full-stream", action="store_true",
                        help="Run full streaming benchmark (WARNING: very slow)")
    args = parser.parse_args()

    hibp_path = args.hibp_path

    if not os.path.exists(hibp_path):
        print(f"ERROR: HIBP file not found: {hibp_path}")
        return 1

    file_size = os.path.getsize(hibp_path)
    file_size_gb = file_size / (1024**3)
    print(f"HIBP file: {hibp_path}")
    print(f"File size: {file_size_gb:.1f} GB")
    print(f"Estimated entries: ~{file_size // 40:,}")
    print()

    # Sample hashes for testing
    hashes = get_sample_hashes(hibp_path, args.count)
    sorted_hashes = sorted(hashes)

    print(f"\n{'='*60}")
    print(f"Benchmarking with {len(hashes)} hashes")
    print(f"{'='*60}\n")

    # Benchmark 1: Binary search (independent lookups)
    print("1. Binary Search (independent lookups)...")
    elapsed, found = benchmark_binary_search(hibp_path, hashes, file_size)
    estimate = estimate_time(elapsed, len(hashes), 600_000)
    print(f"   Time: {elapsed:.2f}s for {len(hashes)} hashes")
    print(f"   Found: {found}/{len(hashes)} ({100*found/len(hashes):.1f}%)")
    print(f"   Per hash: {1000*elapsed/len(hashes):.2f}ms")
    print(f"   Estimate for 600K: {estimate}")
    print()

    # Benchmark 2: Binary search with advancing low bound
    print("2. Binary Search (advancing low bound)...")
    elapsed, found = benchmark_early_exit_binary_search(hibp_path, sorted_hashes, file_size)
    estimate = estimate_time(elapsed, len(sorted_hashes), 600_000)
    print(f"   Time: {elapsed:.2f}s for {len(sorted_hashes)} hashes")
    print(f"   Found: {found}/{len(sorted_hashes)} ({100*found/len(sorted_hashes):.1f}%)")
    print(f"   Per hash: {1000*elapsed/len(sorted_hashes):.2f}ms")
    print(f"   Estimate for 600K: {estimate}")
    print()

    # Only run streaming benchmarks if requested (they're slow)
    if args.full_stream:
        # Benchmark 3: Streaming merge-join (text mode)
        print("3. Streaming Merge-Join (text mode)...")
        print("   WARNING: This reads the entire file - may take hours!")
        elapsed, found = benchmark_streaming_merge_join(hibp_path, sorted_hashes)
        print(f"   Time: {elapsed:.2f}s")
        print(f"   Found: {found}/{len(sorted_hashes)}")
        print()

        # Benchmark 4: Streaming merge-join (binary mode)
        print("4. Streaming Merge-Join (binary mode)...")
        elapsed, found = benchmark_streaming_binary(hibp_path, sorted_hashes)
        print(f"   Time: {elapsed:.2f}s")
        print(f"   Found: {found}/{len(sorted_hashes)}")
        print()

        # Benchmark 5: Streaming with mmap
        print("5. Streaming Merge-Join (mmap)...")
        elapsed, found = benchmark_streaming_mmap(hibp_path, sorted_hashes)
        print(f"   Time: {elapsed:.2f}s")
        print(f"   Found: {found}/{len(sorted_hashes)}")
        print()
    else:
        print("3. Streaming benchmarks skipped (use --full-stream to run)")
        print("   NOTE: Streaming reads entire 74GB file - takes hours in Python")
        print()

    print(f"{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    print()
    print("The streaming merge-join approach is fundamentally flawed for Python:")
    print("  - Reading 1.9B lines in Python is extremely slow")
    print("  - Even at 1M lines/sec, that's 30+ minutes just for I/O")
    print("  - String operations (.strip(), .split(), .upper()) add overhead")
    print()
    print("Recommended approach: Binary search with advancing low bound")
    print("  - Each lookup is O(log n) seeks = ~25-30 seeks")
    print("  - SSDs can do 100K+ random reads/sec")
    print("  - 600K hashes * 30 seeks / 100K seeks/sec ≈ 3 minutes")
    print()

    return 0


if __name__ == "__main__":
    exit(main())
