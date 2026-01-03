# Performance Comparison Report

**Generated:** 2026-01-02
**Laptop:** ThinkPad P1 Gen 4i (njoyzrd-ThinkPad-P1-Gen-4i)
**Server:** kracken3-2

---

## System Specifications

| Specification | Laptop | Server |
|---------------|--------|--------|
| **CPU Model** | Intel Core i9-11950H @ 2.60GHz | Intel Xeon E5-2630 v4 @ 2.20GHz |
| **Architecture** | Tiger Lake (11th Gen, 2021) | Broadwell-EP (2016) |
| **Physical Cores** | 8 | 10 |
| **Logical Threads** | 16 | 40 |
| **Max Frequency** | 4.92 GHz | 3.10 GHz |
| **Memory** | 62.5 GB | 125.8 GB |
| **Storage Type** | NVMe | SSD (SATA) |
| **Free Space** | 67 GB | 2628 GB |
| **OS** | Linux 6.14.0-37-generic | Linux 5.15.0-164-generic |
| **Python** | 3.12.3 | 3.10.12 |
| **HIBP Mode** | SQLite | Binary Search |
| **HIBP Hash Count** | 2.05B | 1.91B |

---

## Performance Comparison

### Step 2: Validation Operations

| Operation | Laptop (avg) | Server (avg) | Laptop Advantage | Notes |
|-----------|--------------|--------------|------------------|-------|
| **Pwdump Validation** | 175,079/s | 84,607/s | **2.07x faster** | Core parsing |
| **Potfile Validation** | 35,311/s | 20,065/s | **1.76x faster** | Small file test |
| **Hash Extraction** | 4,008,968/s | 1,566,181/s | **2.56x faster** | Memory-bound |
| **Validation Total** | 94,589/s | 38,016/s | **2.49x faster** | Combined |
| **Validation Render** | 227,029/s | 87,299/s | **2.60x faster** | Template rendering |

### Step 3: Analysis Operations

| Operation | Laptop (avg) | Server (avg) | Laptop Advantage | Notes |
|-----------|--------------|--------------|------------------|-------|
| **Crack Stats** | 648,441/s | 316,601/s | **2.05x faster** | Statistics calculation |
| **Substring Analysis** | 5,701/s | 3,338/s | **1.71x faster** | CPU-intensive |
| **Dictionary Analysis** | 95,290/s | 61,165/s | **1.56x faster** | Dictionary lookups |
| **Bad Practices** | 1,958/s | 1,135/s | **1.72x faster** | Pattern matching |
| **Password Reuse** | 2,012,047/s | 628,752/s | **3.20x faster** | Hash comparisons |
| **Password History** | 99,352/s | 45,562/s | **2.18x faster** | Historical analysis |

### HIBP Check (Different Modes!)

| Operation | Laptop (SQLite) | Server (Binary Search) | Laptop Advantage |
|-----------|-----------------|------------------------|------------------|
| **HIBP Check** | 184,739/s | 4,825/s | **38.3x faster** |
| **HIBP Result Build** | 901,040/s | 641,238/s | **1.41x faster** |

> **Note:** The HIBP comparison is not apples-to-apples! The laptop uses a SQLite database while the server uses binary search on flat files. SQLite provides massive speedups for random lookups.

### Report Generation

| Operation | Laptop (avg) | Server (avg) | Laptop Advantage | Notes |
|-----------|--------------|--------------|------------------|-------|
| **Report Generation** | 2,101/s | 808/s | **2.60x faster** | Full report |
| **Config Render** | 223,162/s | 120,526/s | **1.85x faster** | Config templating |
| **Config Load** | 213,289/s | 113,271/s | **1.88x faster** | Config parsing |

### Potfile Operations

| Operation | Laptop (avg) | Server (avg) | Laptop Advantage |
|-----------|--------------|--------------|------------------|
| **Master Potfile Merge** | 1,043,496/s | 808,832/s | **1.29x faster** |
| **Master Potfile Count** | 5,795,760/s | 2,307,835/s | **2.51x faster** |

### Startup Time

| Metric | Laptop (avg) | Server | Laptop Advantage |
|--------|--------------|--------|------------------|
| **Total Startup** | 1.36s | 2.41s | **1.77x faster** |
| **Potfile Load** | 1.28s | 2.30s | **1.80x faster** |
| **HIBP Init** | 0.0005s | 0.0002s | Server faster (simpler init) |

---

## Summary Statistics

### Overall Performance Multiplier

| Category | Average Laptop Advantage |
|----------|--------------------------|
| **Validation** | 2.30x |
| **Analysis** | 2.07x |
| **Report Gen** | 2.11x |
| **Potfile Ops** | 1.90x |
| **Startup** | 1.77x |
| **Overall Average** | **~2.0x faster** |

### Key Insights

1. **Single-threaded Performance Wins**: The i9-11950H's superior IPC and higher clock speeds dominate in these workloads which don't heavily parallelize.

2. **Memory Bandwidth**: Modern DDR4-3200 on the laptop vs older DDR4 speeds on the server contributes to the 2.5x+ gains in memory-bound operations.

3. **Storage Impact**: NVMe provides faster random I/O, benefiting operations that hit disk.

4. **HIBP Mode Matters**: SQLite vs binary search is a **38x difference** - consider upgrading the server to SQLite mode.

5. **Architecture Age**: 5 years of CPU improvements (2016 vs 2021) show ~2x single-thread gains.

---

## Recommendations

### For the Server (kracken3-2)

1. **Switch HIBP to SQLite mode** - This alone would provide ~38x speedup for HIBP checks
2. **Consider NVMe storage** for the database files if budget allows
3. **The server excels at parallel workloads** - leverage the 40 threads for batch processing
4. **RAM advantage** - use the 125GB for larger in-memory caches

### For Production Use

- **Interactive/single-report workloads**: Laptop is faster
- **Batch processing multiple reports**: Server can run more in parallel
- **Large datasets**: Server has more RAM headroom
- **HIBP-heavy workloads**: Either system with SQLite mode

---

## Raw Data Reference

### Duration Comparison (Average Seconds)

| Operation | Laptop | Server | Delta |
|-----------|--------|--------|-------|
| Pwdump Validation | 3.73s | 7.68s | -3.95s |
| Hash Extraction | 0.13s | 0.34s | -0.21s |
| Validation Total | 6.82s | 19.56s | -12.74s |
| Crack Stats | 0.13s | 0.26s | -0.13s |
| Substring Analysis | 4.42s | 7.66s | -3.24s |
| Bad Practices | 12.74s | 21.97s | -9.23s |
| HIBP Check | 0.85s | 43.06s | -42.21s |
| Report Generation | 38.67s | 113.16s | -74.49s |
| Password History | 6.50s | 14.16s | -7.66s |

---

*Report generated from timing_stats.json comparison*
