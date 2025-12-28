# Hash Master 1000

A web-based password hash analysis tool for security professionals. Analyze Active Directory password dumps, identify weak passwords, detect patterns, and generate comprehensive security reports.

## Features

### Core Analysis
- **Password Cracking Statistics** - Track crack rates, password lengths, and complexity
- **Password Reuse Detection** - Identify accounts sharing the same password
- **Pattern Analysis** - Detect common password patterns (seasons, years, company terms)
- **Bad Practices Report** - Flag passwords violating security best practices
- **Substring Analysis** - Find common base words and leet-speak variations

### Advanced Analysis
- **Password History Analysis** - Detect predictable password rotation patterns
  - Incrementing numbers: `Password1` → `Password2` → `Password3`
  - Season rotation: `Summer2023` → `Fall2023` → `Winter2024`
  - Year increment: `Company2023` → `Company2024`
  - Special character rotation: `Welcome1!` → `Welcome1@` → `Welcome1#`
  - Hash reuse detection (works without cracking)
  - Predictability scoring (0-100%) for each user

- **Kerberoast Exposure Analysis** - Risk assessment for service accounts with SPNs
- **AS-REP Exposure Analysis** - Identify accounts vulnerable to AS-REP roasting
- **HIBP Integration** - Check passwords against Have I Been Pwned database
- **Historical Trend Analysis** - Compare security metrics across assessments

### Enterprise Features
- **Multi-User Support** - Session-based authentication for team use
- **Session Save/Recall** - Persistent sessions with metadata
- **Master Potfile Integration** - Leverage historical cracking results
- **AD Domain Filtering** - Filter results by Active Directory domain
- **Ollama AI Integration** - AI-powered analysis and report generation

## Supported Input Formats

### Password Dumps
- **PWDump/DCSync format** - Standard `user:rid:lm:ntlm:::` format
- **ADD JSON format** - Active Directory Dumper JSON with extended attributes

### Potfiles
- **Hashcat potfile format** - `hash:password` pairs
- Supports NTLM (mode 1000) hashes

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/hm1k.git
cd hm1k

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template and configure
cp .env.example .env
# Edit .env with your settings

# Run the application
python hm1k.py
```

## Configuration

Configure via `.env` file:

```env
# Server settings
SECRET_KEY=your-secret-key
HOST=127.0.0.1
PORT=5000

# Authentication
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD=changeme

# Master potfile (optional)
MASTER_POTFILE_ENABLED=false
MASTER_POTFILE_PATH=/path/to/master.potfile

# HIBP integration (optional)
HIBP_ENABLED=false
HIBP_DB_PATH=/path/to/hibp.txt

# Ollama AI (optional)
OLLAMA_ENABLED=false
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

## Usage

1. Navigate to `http://localhost:5000` in your browser
2. Upload your password dump file (pwdump or ADD JSON format)
3. Upload your potfile with cracked hashes
4. Configure analysis options (exclude computer accounts, blank passwords, etc.)
5. Click "Analyze" to generate the report
6. Explore interactive charts and tables
7. Export findings as needed

## Password History Analysis

When password history data is available (via `_history` suffixes in pwdump or `HistoricalNTHashes` in ADD JSON), Hash Master 1000 analyzes password evolution patterns:

### Predictability Scoring

| Pattern Type | Weight | Description |
|-------------|--------|-------------|
| Consecutive Hash Reuse | 55% | Same password used repeatedly |
| Incrementing Number | 45% | Trivial increment (`Password1` → `Password2`) |
| Year Increment | 45% | Year-based pattern (`2023` → `2024`) |
| Season Rotation | 40% | Seasonal pattern (4 options to try) |
| Password Reversion | 35% | Returns to previously used password |
| Special Char Rotation | 35% | Limited character set (~10 chars) |
| Minimal Changes | 30% | 1-2 character differences |
| Base Word Persistence | 20% | Same root word across changes |
| Leet Progression | 15% | Character substitutions |

### Score Interpretation
- **100%**: Always uses the same password
- **70%+** (Critical): Next password is trivially guessable
- **40-69%** (High): Strong patterns make guessing feasible
- **Below 40%** (Medium): Some patterns but harder to exploit

## Security Considerations

- This tool handles sensitive password data - deploy on secure, isolated networks
- Enable authentication in production environments
- Potfiles and session data contain cracked passwords - handle appropriately
- Consider encryption at rest for stored session data

## License

Internal tool - not for public distribution.

---

*Last Updated: December 2024*
