"""
Ollama Prompt Templates for HM1K

All prompts used for AI-powered password analysis are stored here for easy
editing and review. These prompts are critical for tuning the AI responses.

Active AAIA Pipelines:
- Semantic Password Intelligence (SPI): See app/spi_prompts.py
- Company Intelligence (CI): See app/company_intel_prompts.py
- Account Description Inspector (DA): See app/description_llm_prompts.py

Usage:
    from ollama_prompts import SYSTEM_PROMPT
"""

# =============================================================================
# SYSTEM PROMPT
# =============================================================================
# This prompt sets the context and persona for the AI. It's sent with every
# request to establish the AI's role and expertise.

SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in password security. You recently completed an Active Directory domain password assessment by collecting (dumping) the domain hashes and then running them through hashcat doing multiple rounds of brute force guessing (up to 9 character passwords), dictionary attacks, hybrid dictionary attacks with rules (like One Rule to Rule them All) and mask attacks. Your job is to analyze the domain dump output and the hashcat output, and be prepared to answer questions about your analysis so your user can report your findings."""


# =============================================================================
# DEFAULT TEST PAGE PROMPTS
# =============================================================================
# Default values shown in the test page UI.

DEFAULT_USER_PROMPT = "Analyze the security implications of users choosing \"Summer2024\" as their password."

DEFAULT_STATS_JSON = {
    "total_accounts": 5000,
    "cracked_accounts": 3350,
    "cracked_percent": 67,
    "unique_passwords": 2100,
    "avg_length": 9.2,
    "min_length": 4,
    "max_length": 24,
    "blank_passwords": 12
}

DEFAULT_PATTERNS_JSON = {
    "Password Variants": {"count": 234, "examples": {"P@ssw0rd": 45, "password123": 32}},
    "Season + Year": {"count": 567, "examples": {"Summer2024": 89, "Winter2023": 45}},
    "Keyboard Walks": {"count": 123, "examples": {"qwerty123": 34}}
}

DEFAULT_CLUSTER_PASSWORDS = """Summer2024
Winter2023!
GoPackers!
yankees123
JohnSmith1
password123
Welcome1!
Jesus2024
NewYork99
football!"""


# -----------------------------------------------------------------------------
# AI Report Section Configuration
# -----------------------------------------------------------------------------
# Maps section IDs to their prompts, recommended settings, and data sources.
# Only active AAIA pipelines are listed here.
#
# data_sources: Maps prompt variable names to their JSON file sources
#   - "file:<filename>" = Load from /data/<filename>.json
#   - "derived:<function>" = Compute from other data (handled in code)
#   - "session:<key>" = Load from Flask session
#   - "config:<key>" = Load from analysis configuration

AI_REPORT_SECTIONS = {
    "weak-habits": {
        "title": "Semantic Password Intelligence",
        "description": "AI extracts semantic patterns (sports, pop culture, profanity, etc.) that regex cannot detect",
        "enabled": True,
        "pipeline": "spi",  # Uses Semantic Password Intelligence pipeline instead of standard 3-phase
        "recommended_model": "llama3.1:70b",
        "temperature": 0.2,  # Lower temp for consistent extraction
        "order": 1,
        "data_sources": {
            # SPI uses its own data loading - these are for reference only
            "cracked_passwords": "derived:all_cracked_passwords"
        }
    },
    "company-intel": {
        "title": "Company Intelligence",
        "description": "Infers company identity, industry, and location from raw passwords and account names",
        "enabled": True,
        "pipeline": "company_intel",  # Uses Company Intelligence pipeline with 3 focused prompts
        "recommended_model": "deepseek-r1:671b",
        "temperature": 0.3,  # 671B excels at inference - worth the extra time
        "order": 2,
        "data_sources": {
            # Raw data for independent AI analysis
            "cracked_passwords": "derived:all_cracked_passwords",
            "account_names": "derived:all_account_names",
            "org_context": "derived:organizational_context",
            "total_accounts": "derived:total_account_count",
            "cracked_count": "derived:cracked_account_count"
        }
    },
    "description-analysis": {
        "title": "Account Description Inspector",
        "description": "LLM-enhanced detection of passwords, PII, and credentials in AD account descriptions",
        "enabled": True,
        "pipeline": "description_llm",  # Uses chunked LLM analysis for complete coverage
        "recommended_model": "llama3.1:70b",
        "temperature": 0.1,  # Low temp for precise extraction
        "order": 3,
        "requires_add_json": True,  # Only available for ADD JSON sessions
        "data_sources": {
            "users_with_descriptions": "derived:users_with_descriptions"
        },
        "chunk_config": {
            "default_chunk_size": 100,
            "min_chunk_size": 25,
            "max_chunk_size": 500
        }
    }
}


# =============================================================================
# LEGACY VALIDATION/FORMATTING PROMPTS (Deprecated)
# =============================================================================
# These prompts were used for the old 3-phase pipeline. The active AAIA
# pipelines (SPI, CI, DA) now use Python-based validation and formatting.
# Keeping these for reference but they are no longer used.

VALIDATION_PROMPTS: dict[str, str] = {}
FORMATTING_PROMPTS: dict[str, str] = {}

def get_validation_prompt(section_id: str) -> str:
    """Legacy function - validation is now Python-based for active pipelines."""
    return ""

def get_formatting_prompt(section_id: str) -> str:
    """Legacy function - formatting is now Python-based for active pipelines."""
    return ""


# =============================================================================
# Phase Configuration for AI Report Sections
# =============================================================================
# Defines model and temperature settings for each active AAIA pipeline.
# All active pipelines use Python-based validation and formatting (no Phase 2/3).

PHASE_CONFIG = {
    "weak-habits": {
        # Uses SPI pipeline - runs 11 focused category prompts, Python validates and formats
        "pipeline": "spi",
        "phase1": {"model": "llama3.1:70b", "temperature": 0.2},  # Used for each SPI category
        "phase2": {"model": None, "temperature": None, "enabled": False},  # Python validates
        "phase3": {"model": None, "temperature": None, "enabled": False},  # Python formats
        "evidence_sources": []  # SPI generates its own evidence from validated matches
    },
    "company-intel": {
        # Uses Company Intel pipeline - runs 3 focused category prompts
        "pipeline": "company_intel",
        "phase1": {"model": "deepseek-r1:671b", "temperature": 0.3},  # Used for each CI category
        "phase2": {"model": None, "temperature": None, "enabled": False},  # Findings are from LLM extraction
        "phase3": {"model": None, "temperature": None, "enabled": False},  # Markdown formatted by Python
        "evidence_sources": []  # CI generates its own evidence from analyzed data
    },
    "description-analysis": {
        # Uses Description LLM pipeline - chunked analysis of AD account descriptions
        "pipeline": "description_llm",
        "phase1": {"model": "llama3.1:70b", "temperature": 0.1},  # Low temp for precise extraction
        "phase2": {"model": None, "temperature": None, "enabled": False},  # Python validates (hallucination detection)
        "phase3": {"model": None, "temperature": None, "enabled": False},  # HTML formatted by Python
        "evidence_sources": []  # DA generates its own evidence from account descriptions
    }
}


def get_phase_config(section_id: str) -> dict:
    """Get the phase configuration for a specific section."""
    return PHASE_CONFIG.get(section_id, {
        "pipeline": "unknown",
        "phase1": {"model": "llama3.1:70b", "temperature": 0.3},
        "phase2": {"model": None, "temperature": None, "enabled": False},
        "phase3": {"model": None, "temperature": None, "enabled": False},
        "evidence_sources": []
    })
