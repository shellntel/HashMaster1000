"""
Ollama Integration Toolkit for HM1K

This module provides AI-powered analysis capabilities using a local Ollama server.
Currently a hidden/experimental feature for internal testing.

Features:
- Executive Summary Generation
- Semantic Password Clustering
- Natural Language Pattern Description
- Attack Strategy Recommendations
"""

import os
import json
import requests
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

from ollama_prompts import (
    SYSTEM_PROMPT,
    EXECUTIVE_SUMMARY_PROMPT,
    PATTERN_DESCRIPTION_PROMPT,
    SEMANTIC_CLUSTERING_PROMPT,
    ATTACK_STRATEGY_PROMPT,
    BATCH_ANALYSIS_PROMPTS,
    # AI Report Section Prompts
    WEAK_HABITS_PROMPT,
    COMPANY_INTEL_PROMPT,
    USER_BEHAVIOR_PROMPT,
    RISK_ASSESSMENT_PROMPT,
    RECOMMENDATIONS_PROMPT,
    FULL_REPORT_PROMPT,
    AI_REPORT_SECTIONS,
)


@dataclass
class OllamaConfig:
    """Configuration for Ollama API connection."""
    host: str = "http://localhost:11434"
    timeout: int = 120
    enabled: bool = False


@dataclass
class OllamaServer:
    """Configuration for a single Ollama server."""
    id: str
    name: str
    host: str
    description: str = ""
    hardware: str = ""


# Multi-server configuration
# Servers are loaded from environment variables with fallback to defaults
def get_ollama_servers() -> List[OllamaServer]:
    """Get list of configured Ollama servers."""
    servers = []

    # Primary server from OLLAMA_HOST
    primary_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    servers.append(OllamaServer(
        id="primary",
        name=os.getenv("OLLAMA_PRIMARY_NAME", "Primary Server"),
        host=primary_host,
        description=os.getenv("OLLAMA_PRIMARY_DESC", "Default Ollama server"),
        hardware=os.getenv("OLLAMA_PRIMARY_HARDWARE", "")
    ))

    # Secondary server (optional)
    secondary_host = os.getenv("OLLAMA_SECONDARY_HOST", "")
    if secondary_host:
        servers.append(OllamaServer(
            id="secondary",
            name=os.getenv("OLLAMA_SECONDARY_NAME", "Secondary Server"),
            host=secondary_host,
            description=os.getenv("OLLAMA_SECONDARY_DESC", "Secondary Ollama server"),
            hardware=os.getenv("OLLAMA_SECONDARY_HARDWARE", "")
        ))

    # Tertiary server (optional)
    tertiary_host = os.getenv("OLLAMA_TERTIARY_HOST", "")
    if tertiary_host:
        servers.append(OllamaServer(
            id="tertiary",
            name=os.getenv("OLLAMA_TERTIARY_NAME", "Tertiary Server"),
            host=tertiary_host,
            description=os.getenv("OLLAMA_TERTIARY_DESC", "Tertiary Ollama server"),
            hardware=os.getenv("OLLAMA_TERTIARY_HARDWARE", "")
        ))

    return servers


def get_server_by_id(server_id: str) -> Optional[OllamaServer]:
    """Get a specific server by its ID."""
    servers = get_ollama_servers()
    for server in servers:
        if server.id == server_id:
            return server
    return None


def get_ollama_config(server_id: Optional[str] = None) -> OllamaConfig:
    """Load Ollama configuration from environment variables.

    Args:
        server_id: Optional server ID to get config for specific server
    """
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    enabled = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"

    if server_id:
        server = get_server_by_id(server_id)
        if server:
            return OllamaConfig(
                host=server.host,
                timeout=timeout,
                enabled=enabled
            )

    return OllamaConfig(
        host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        timeout=timeout,
        enabled=enabled
    )


class OllamaClient:
    """Client for interacting with Ollama API."""

    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or get_ollama_config()
        self._available_models: Optional[List[str]] = None

    def is_available(self) -> bool:
        """Check if Ollama server is reachable."""
        if not self.config.enabled:
            return False
        try:
            response = requests.get(
                f"{self.config.host}/api/tags",
                timeout=5
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def list_models(self) -> List[str]:
        """Get list of available models from Ollama server."""
        if self._available_models is not None:
            return self._available_models

        try:
            response = requests.get(
                f"{self.config.host}/api/tags",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self._available_models = [m["name"] for m in data.get("models", [])]
                return self._available_models
        except requests.RequestException:
            pass
        return []

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> Optional[str]:
        """
        Generate a response from the Ollama model.

        Args:
            prompt: The user prompt
            system: Optional system prompt
            model: Model to use (defaults to config model)
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text or None if failed
        """
        if not self.config.enabled:
            return None

        if not model:
            return None

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }

        if system:
            payload["system"] = system

        if max_tokens:
            payload["options"]["num_predict"] = max_tokens

        try:
            response = requests.post(
                f"{self.config.host}/api/generate",
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("response", "")
            else:
                print(f"Ollama API error: {response.status_code} - {response.text}")
                return None

        except requests.RequestException as e:
            print(f"Ollama request failed: {e}")
            return None

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7
    ) -> Optional[str]:
        """
        Send a chat conversation to the Ollama model.

        Args:
            messages: List of {"role": "user"|"assistant"|"system", "content": "..."}
            model: Model to use (defaults to config model)
            temperature: Sampling temperature

        Returns:
            Generated response or None if failed
        """
        if not self.config.enabled:
            return None

        if not model:
            return None

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }

        try:
            response = requests.post(
                f"{self.config.host}/api/chat",
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("message", {}).get("content", "")
            else:
                print(f"Ollama API error: {response.status_code} - {response.text}")
                return None

        except requests.RequestException as e:
            print(f"Ollama request failed: {e}")
            return None


# =============================================================================
# Analysis Functions
# =============================================================================

class PasswordAnalysisAI:
    """AI-powered password analysis using Ollama."""

    def __init__(self, client: Optional[OllamaClient] = None, model: Optional[str] = None):
        self.client = client or OllamaClient()
        self.model = model

    def generate_executive_summary(
        self,
        stats: Dict[str, Any],
        patterns: Dict[str, Any],
        critical_findings: List[str],
        model: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate an executive summary of the password audit.

        Args:
            stats: Dictionary with total_accounts, cracked_accounts, etc.
            patterns: Dictionary of pattern names to counts
            critical_findings: List of critical finding descriptions

        Returns:
            Executive summary text or None if failed
        """
        # Format patterns for the prompt
        pattern_lines = []
        for name, data in patterns.items():
            if isinstance(data, dict) and "count" in data:
                count = data["count"]
                if count > 0:
                    pattern_lines.append(f"- {name}: {count} passwords")
            elif isinstance(data, int) and data > 0:
                pattern_lines.append(f"- {name}: {data} passwords")

        patterns_text = "\n".join(pattern_lines) if pattern_lines else "No significant patterns detected"

        # Format critical findings
        findings_text = "\n".join(f"- {f}" for f in critical_findings) if critical_findings else "No critical findings"

        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            total_accounts=stats.get("total_accounts", 0),
            cracked_accounts=stats.get("cracked_accounts", 0),
            cracked_percent=stats.get("cracked_percent", 0),
            unique_passwords=stats.get("unique_passwords", 0),
            avg_length=stats.get("avg_length", 0),
            min_length=stats.get("min_length", 0),
            max_length=stats.get("max_length", 0),
            blank_passwords=stats.get("blank_passwords", 0),
            patterns=patterns_text,
            critical_findings=findings_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.7
        )

    def describe_patterns(self, pattern_data: Dict[str, Any], model: Optional[str] = None) -> Optional[str]:
        """
        Generate natural language descriptions of password patterns.

        Args:
            pattern_data: Dictionary of patterns with counts and examples

        Returns:
            Pattern analysis text or None if failed
        """
        # Format pattern data for the prompt
        formatted = json.dumps(pattern_data, indent=2, default=str)

        prompt = PATTERN_DESCRIPTION_PROMPT.format(pattern_data=formatted)

        return self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.5
        )

    def cluster_passwords_semantically(
        self,
        passwords: List[str],
        sample_size: int = 500,
        model: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Categorize passwords by semantic meaning.

        Args:
            passwords: List of passwords to analyze
            sample_size: Max passwords to send (for token limits)

        Returns:
            Dictionary with categories and insights or None if failed
        """
        # Sample if too many passwords
        if len(passwords) > sample_size:
            import random
            passwords = random.sample(passwords, sample_size)

        # Format passwords (one per line)
        passwords_text = "\n".join(passwords)

        prompt = SEMANTIC_CLUSTERING_PROMPT.format(passwords=passwords_text)

        response = self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.3  # Lower temperature for more consistent JSON
        )

        if response:
            # Try to parse JSON from response
            try:
                # Find JSON in response (it might have text before/after)
                start = response.find("{")
                end = response.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(response[start:end])
            except json.JSONDecodeError:
                # Return raw response if JSON parsing fails
                return {"raw_response": response}

        return None

    def recommend_attack_strategy(
        self,
        patterns: Dict[str, Any],
        stats: Dict[str, Any],
        base_words: List[str],
        structures: List[str],
        model: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate attack strategy recommendations for remaining hashes.

        Args:
            patterns: Observed patterns in cracked passwords
            stats: Cracking statistics
            base_words: Most common base words found
            structures: Most common password structures
            model: Model to use for generation

        Returns:
            Attack strategy text or None if failed
        """
        patterns_text = json.dumps(patterns, indent=2, default=str)
        base_words_text = "\n".join(f"- {w}" for w in base_words[:20])
        structures_text = "\n".join(f"- {s}" for s in structures[:20])

        prompt = ATTACK_STRATEGY_PROMPT.format(
            patterns=patterns_text,
            total_hashes=stats.get("total_hashes", 0),
            cracked=stats.get("cracked", 0),
            cracked_percent=stats.get("cracked_percent", 0),
            remaining=stats.get("remaining", 0),
            base_words=base_words_text,
            structures=structures_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.5
        )

    def analyze_password_batch(
        self,
        passwords: List[str],
        analysis_type: str = "general",
        model: Optional[str] = None
    ) -> Optional[str]:
        """
        Generic password batch analysis.

        Args:
            passwords: List of passwords
            analysis_type: Type of analysis ("general", "weakness", "theme")

        Returns:
            Analysis text or None if failed
        """
        prompt_template = BATCH_ANALYSIS_PROMPTS.get(analysis_type, BATCH_ANALYSIS_PROMPTS["general"])
        passwords_text = "\n".join(passwords[:200])  # Limit for token size

        return self.client.generate(
            prompt=prompt_template.format(passwords=passwords_text),
            model=model or self.model,
            system=SYSTEM_PROMPT,
            temperature=0.6
        )


# =============================================================================
# AI Report Section Analysis
# =============================================================================

class AIReportAnalyzer:
    """Generates AI analysis for report sections."""

    def __init__(self, client: Optional[OllamaClient] = None):
        self.client = client or OllamaClient()

    def get_section_config(self, section_id: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a report section."""
        return AI_REPORT_SECTIONS.get(section_id)

    def get_all_sections(self) -> Dict[str, Any]:
        """Get all section configurations sorted by order."""
        sections = dict(sorted(
            AI_REPORT_SECTIONS.items(),
            key=lambda x: x[1].get("order", 99)
        ))
        return sections

    def analyze_weak_habits(
        self,
        cracked_passwords: str,
        account_passwords: str,
        password_reuse: str,
        org_context: str,
        total_accounts: int,
        cracked_count: int,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Analyze weak password habits using raw password data.

        This method sends raw password data to the LLM for independent pattern
        discovery, rather than relying on pre-processed categories.

        Args:
            cracked_passwords: All cracked passwords as formatted string
            account_passwords: Account:password pairs for context
            password_reuse: Password reuse details
            org_context: Organizational context (domains, account types)
            total_accounts: Total number of accounts analyzed
            cracked_count: Number of passwords cracked
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting (defaults to section recommendation)
        """
        config = self.get_section_config("weak-habits")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = WEAK_HABITS_PROMPT.format(
            cracked_passwords=cracked_passwords,
            account_passwords=account_passwords,
            password_reuse=password_reuse,
            org_context=org_context,
            total_accounts=total_accounts,
            cracked_count=cracked_count
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def analyze_company_intel(
        self,
        cracked_passwords: str,
        account_names: str,
        org_context: str,
        total_accounts: int,
        cracked_count: int,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Analyze passwords and account names to infer company information.

        This method sends raw data to the LLM for independent discovery of
        company-identifying information like company name, industry, location.

        Args:
            cracked_passwords: All cracked passwords as formatted string
            account_names: All account names grouped by domain
            org_context: Organizational context (domains, account types)
            total_accounts: Total number of accounts analyzed
            cracked_count: Number of passwords cracked
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting (defaults to section recommendation)
        """
        config = self.get_section_config("company-intel")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = COMPANY_INTEL_PROMPT.format(
            cracked_passwords=cracked_passwords,
            account_names=account_names,
            org_context=org_context,
            total_accounts=total_accounts,
            cracked_count=cracked_count
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def analyze_user_behavior(
        self,
        cracked_passwords: str,
        account_passwords: str,
        password_reuse: str,
        org_context: str,
        total_accounts: int,
        cracked_count: int,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Analyze user psychology and behavior patterns from raw password data.

        This method sends raw password data to the LLM for independent behavioral
        analysis, rather than relying on pre-processed categories.

        Args:
            cracked_passwords: All cracked passwords as formatted string
            account_passwords: Account:password pairs for context
            password_reuse: Password reuse details
            org_context: Organizational context (domains, account types)
            total_accounts: Total number of accounts analyzed
            cracked_count: Number of passwords cracked
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting (defaults to section recommendation)
        """
        config = self.get_section_config("user-behavior")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = USER_BEHAVIOR_PROMPT.format(
            cracked_passwords=cracked_passwords,
            account_passwords=account_passwords,
            password_reuse=password_reuse,
            org_context=org_context,
            total_accounts=total_accounts,
            cracked_count=cracked_count
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def analyze_risk(
        self,
        stats: Dict[str, Any],
        policy_failures: Dict[str, int],
        critical_findings: List[str],
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generate risk assessment.

        Args:
            stats: Password audit statistics
            policy_failures: Counts of policy failures by type
            critical_findings: List of critical findings
            model: Model to use
            temperature: Temperature setting
        """
        config = self.get_section_config("risk-assessment")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        stats_text = "\n".join(f"- {k}: {v}" for k, v in stats.items())
        failures_text = "\n".join(f"- {policy}: {count} accounts" for policy, count in policy_failures.items())
        findings_text = "\n".join(f"- {f}" for f in critical_findings) if critical_findings else "None identified"

        prompt = RISK_ASSESSMENT_PROMPT.format(
            stats=stats_text,
            policy_failures=failures_text,
            critical_findings=findings_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def generate_recommendations(
        self,
        key_findings: List[str],
        current_policy: Dict[str, Any],
        worst_practices: List[str],
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generate security recommendations.

        Args:
            key_findings: Summary of key findings
            current_policy: Current password policy settings
            worst_practices: Worst password practices observed
            model: Model to use
            temperature: Temperature setting
        """
        config = self.get_section_config("recommendations")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        findings_text = "\n".join(f"- {f}" for f in key_findings)
        policy_text = "\n".join(f"- {k}: {v}" for k, v in current_policy.items())
        practices_text = "\n".join(f"- {p}" for p in worst_practices)

        prompt = RECOMMENDATIONS_PROMPT.format(
            key_findings=findings_text,
            current_policy=policy_text,
            worst_practices=practices_text
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def generate_full_report(
        self,
        audit_stats: str,
        org_context: str,
        weak_habits_analysis: str,
        company_intel_analysis: str,
        user_behavior_analysis: str,
        risk_assessment_analysis: str,
        recommendations_analysis: str,
        raw_data_summary: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generate a comprehensive security assessment report.

        This method synthesizes all prior AI analyses into a cohesive,
        board-ready report. It should be called after all other sections
        have been generated.

        Args:
            audit_stats: Complete cracking statistics
            org_context: Organizational context
            weak_habits_analysis: Output from weak-habits section
            company_intel_analysis: Output from company-intel section
            user_behavior_analysis: Output from user-behavior section
            risk_assessment_analysis: Output from risk-assessment section
            recommendations_analysis: Output from recommendations section
            raw_data_summary: Summary of raw JSON data
            model: Model to use (defaults to section recommendation)
            temperature: Temperature setting
        """
        config = self.get_section_config("full-report")
        model = model or config["recommended_model"]
        temperature = temperature if temperature is not None else config["temperature"]

        prompt = FULL_REPORT_PROMPT.format(
            audit_stats=audit_stats,
            org_context=org_context,
            weak_habits_analysis=weak_habits_analysis or "[Not yet generated]",
            company_intel_analysis=company_intel_analysis or "[Not yet generated]",
            user_behavior_analysis=user_behavior_analysis or "[Not yet generated]",
            risk_assessment_analysis=risk_assessment_analysis or "[Not yet generated]",
            recommendations_analysis=recommendations_analysis or "[Not yet generated]",
            raw_data_summary=raw_data_summary
        )

        return self.client.generate(
            prompt=prompt,
            model=model,
            system=SYSTEM_PROMPT,
            temperature=temperature
        )

    def generate_section(
        self,
        section_id: str,
        data: Dict[str, Any],
        model: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[str]:
        """
        Generic method to generate any section by ID.

        Args:
            section_id: The section identifier (e.g., "weak-habits")
            data: Dictionary containing all required data for the prompt
            model: Override model selection
            temperature: Override temperature
        """
        config = self.get_section_config(section_id)
        if not config:
            return None

        # Map section IDs to their analysis methods
        section_methods = {
            "weak-habits": lambda: self.analyze_weak_habits(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_passwords=data.get("account_passwords", ""),
                password_reuse=data.get("password_reuse", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0),
                model=model,
                temperature=temperature
            ),
            "company-intel": lambda: self.analyze_company_intel(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_names=data.get("account_names", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0),
                model=model,
                temperature=temperature
            ),
            "user-behavior": lambda: self.analyze_user_behavior(
                cracked_passwords=data.get("cracked_passwords", ""),
                account_passwords=data.get("account_passwords", ""),
                password_reuse=data.get("password_reuse", ""),
                org_context=data.get("org_context", ""),
                total_accounts=data.get("total_accounts", 0),
                cracked_count=data.get("cracked_count", 0),
                model=model,
                temperature=temperature
            ),
            "risk-assessment": lambda: self.analyze_risk(
                stats=data.get("stats", {}),
                policy_failures=data.get("policy_failures", {}),
                critical_findings=data.get("critical_findings", []),
                model=model,
                temperature=temperature
            ),
            "recommendations": lambda: self.generate_recommendations(
                key_findings=data.get("key_findings", []),
                current_policy=data.get("current_policy", {}),
                worst_practices=data.get("worst_practices", []),
                model=model,
                temperature=temperature
            ),
            "full-report": lambda: self.generate_full_report(
                audit_stats=data.get("audit_stats", ""),
                org_context=data.get("org_context", ""),
                weak_habits_analysis=data.get("weak_habits_analysis", ""),
                company_intel_analysis=data.get("company_intel_analysis", ""),
                user_behavior_analysis=data.get("user_behavior_analysis", ""),
                risk_assessment_analysis=data.get("risk_assessment_analysis", ""),
                recommendations_analysis=data.get("recommendations_analysis", ""),
                raw_data_summary=data.get("raw_data_summary", ""),
                model=model,
                temperature=temperature
            )
        }

        method = section_methods.get(section_id)
        if method:
            return method()
        return None


def get_ai_report_sections() -> Dict[str, Any]:
    """Get all AI report section configurations."""
    return AI_REPORT_SECTIONS


# =============================================================================
# AI Report Data Loader
# =============================================================================

class AIReportDataLoader:
    """
    Loads and transforms analysis data for AI report sections.

    Handles loading data from:
    - JSON files in /data directory
    - Flask session
    - Derived computations from other data
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self._cache: Dict[str, Any] = {}

    def _load_json_file(self, filename: str) -> Any:
        """Load a JSON file from the data directory."""
        if filename in self._cache:
            return self._cache[filename]

        filepath = os.path.join(self.data_dir, f"{filename}.json")
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                self._cache[filename] = data
                return data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading {filepath}: {e}")
            return None

    def _derive_password_samples(self, limit: int = 200) -> List[str]:
        """Extract password samples from top_passwords and account_data."""
        samples = []

        # Get from top passwords
        top_pw = self._load_json_file("pw_top_passwords")
        if top_pw and isinstance(top_pw, dict):
            samples.extend([pw for pw in top_pw.keys() if pw and pw != "{blank}"])

        # If we need more, get from account_data
        if len(samples) < limit:
            account_data = self._load_json_file("account_data")
            if account_data and isinstance(account_data, dict):
                for account in account_data.values():
                    pw = account.get("cracked_pw")
                    if pw and pw not in samples:
                        samples.append(pw)
                    if len(samples) >= limit:
                        break

        return samples[:limit]

    def _derive_company_terms(self) -> List[str]:
        """Extract company-specific terms from bad practices."""
        bad_practices = self._load_json_file("pw_bad_practices")
        if not bad_practices:
            return []

        company_terms_data = bad_practices.get("Company Terms", {})
        if isinstance(company_terms_data, dict):
            examples = company_terms_data.get("examples", {})
            return list(examples.keys()) if isinstance(examples, dict) else []
        return []

    # -------------------------------------------------------------------------
    # New derive functions for raw password analysis (Weak Habits section)
    # -------------------------------------------------------------------------

    def _derive_all_cracked_passwords(self) -> str:
        """
        Get all cracked passwords as a formatted string for LLM analysis.
        Returns unique passwords with their frequency counts.
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No password data available"

        # Count password frequencies
        password_counts: Dict[str, int] = {}
        for account in account_data.values():
            pw = account.get("cracked_pw")
            if pw:
                password_counts[pw] = password_counts.get(pw, 0) + 1

        if not password_counts:
            return "No cracked passwords found"

        # Sort by frequency (most common first), then alphabetically
        sorted_passwords = sorted(
            password_counts.items(),
            key=lambda x: (-x[1], x[0])
        )

        # Format as list with counts for passwords used more than once
        lines = []
        for pw, count in sorted_passwords:
            if count > 1:
                lines.append(f"{pw} (x{count})")
            else:
                lines.append(pw)

        return "\n".join(lines)

    def _derive_account_password_pairs(self, limit: int = 100) -> str:
        """
        Get account:password pairs to show username-password relationships.
        Samples accounts to avoid overwhelming the prompt.
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No account data available"

        pairs = []
        for username, data in account_data.items():
            pw = data.get("cracked_pw")
            if pw:
                # Simplify username (remove domain if present)
                simple_name = username.split("\\")[-1] if "\\" in username else username
                pairs.append(f"{simple_name}: {pw}")
                if len(pairs) >= limit:
                    break

        if not pairs:
            return "No cracked account-password pairs found"

        return "\n".join(pairs)

    def _derive_all_account_names(self) -> str:
        """
        Get all account names for company intelligence analysis.
        Includes full usernames with domains to help identify company.
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No account data available"

        # Group accounts by domain for easier analysis
        domains: Dict[str, List[str]] = {}
        no_domain: List[str] = []

        for username in account_data.keys():
            if "\\" in username:
                domain, name = username.split("\\", 1)
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append(name)
            else:
                no_domain.append(username)

        lines = []

        # Output by domain
        for domain in sorted(domains.keys()):
            lines.append(f"=== Domain: {domain} ===")
            # Sort accounts alphabetically within domain
            for account in sorted(domains[domain]):
                lines.append(account)
            lines.append("")

        # Output accounts without domain
        if no_domain:
            lines.append("=== No Domain ===")
            for account in sorted(no_domain):
                lines.append(account)

        return "\n".join(lines)

    def _derive_password_reuse_details(self) -> str:
        """
        Get details about passwords shared across multiple accounts.
        """
        reuse_data = self._load_json_file("pw_reuse_table")
        account_data = self._load_json_file("account_data")

        if not reuse_data or not account_data:
            return "No password reuse data available"

        # Build hash-to-password mapping
        hash_to_pw: Dict[str, str] = {}
        for username, data in account_data.items():
            ntlm = data.get("ntlm_hash")
            pw = data.get("cracked_pw")
            if ntlm and pw:
                hash_to_pw[ntlm] = pw

        cracked_reuse = []
        uncracked_reuse = []

        for item in reuse_data:
            if isinstance(item, list) and len(item) >= 3:
                hash_val, count, accounts = item[0], item[1], item[2]
                if count > 1:
                    pw = hash_to_pw.get(hash_val)
                    account_list = ", ".join(accounts[:5])
                    if len(accounts) > 5:
                        account_list += f" (+{len(accounts)-5} more)"

                    if pw:
                        # Password was cracked - show the password
                        cracked_reuse.append((count, f"'{pw}' shared by {count} accounts: {account_list}"))
                    else:
                        # Password not cracked - check for known hashes and show hash info
                        if hash_val == "31d6cfe0d16ae931b73c59d7e0c089c0":
                            cracked_reuse.append((count, f"'{{blank}}' shared by {count} accounts: {account_list}"))
                        else:
                            # Show truncated hash for uncracked shared passwords
                            hash_preview = hash_val[:8] + "..." if len(hash_val) > 8 else hash_val
                            uncracked_reuse.append((count, f"[UNCRACKED HASH: {hash_preview}] shared by {count} accounts: {account_list}"))

        if not cracked_reuse and not uncracked_reuse:
            return "No significant password reuse detected"

        # Sort by count (most reused first) and combine
        cracked_reuse.sort(key=lambda x: x[0], reverse=True)
        uncracked_reuse.sort(key=lambda x: x[0], reverse=True)

        lines = []
        if cracked_reuse:
            lines.append("=== Cracked Password Reuse ===")
            lines.extend([item[1] for item in cracked_reuse[:20]])

        if uncracked_reuse:
            if lines:
                lines.append("")
            lines.append("=== Uncracked Hash Reuse (same unknown password) ===")
            lines.extend([item[1] for item in uncracked_reuse[:10]])

        return "\n".join(lines)

    def _derive_organizational_context(self) -> str:
        """
        Extract organizational context from account data (domains, account types, etc.)
        """
        account_data = self._load_json_file("account_data")
        if not account_data:
            return "No organizational context available"

        domains = set()
        account_types = {
            "user": 0,
            "computer": 0,
            "service": 0,
            "admin": 0
        }

        for username in account_data.keys():
            # Extract domain
            if "\\" in username:
                domain = username.split("\\")[0]
                domains.add(domain)

            # Classify account type
            lower_name = username.lower()
            if lower_name.endswith("$"):
                account_types["computer"] += 1
            elif any(x in lower_name for x in ["svc", "service", "sql", "app"]):
                account_types["service"] += 1
            elif any(x in lower_name for x in ["admin", "adm", "root"]):
                account_types["admin"] += 1
            else:
                account_types["user"] += 1

        lines = []
        if domains:
            lines.append(f"Domains detected: {', '.join(sorted(domains))}")

        type_summary = ", ".join(f"{t}: {c}" for t, c in account_types.items() if c > 0)
        if type_summary:
            lines.append(f"Account types: {type_summary}")

        return "\n".join(lines) if lines else "No organizational context detected"

    def _derive_total_account_count(self) -> int:
        """Get total number of accounts."""
        account_data = self._load_json_file("account_data")
        return len(account_data) if account_data else 0

    def _derive_cracked_account_count(self) -> int:
        """Get number of accounts with cracked passwords."""
        account_data = self._load_json_file("account_data")
        if not account_data:
            return 0
        return sum(1 for acc in account_data.values() if acc.get("cracked_pw"))

    def _derive_policy_failures(self) -> Dict[str, int]:
        """Compile policy failure counts from multiple JSON files."""
        failures = {}

        # Min length failures
        min_length = self._load_json_file("pw_fails_min_length")
        if min_length:
            failures["Minimum Length"] = len(min_length) if isinstance(min_length, dict) else 0

        # Complexity failures
        complexity = self._load_json_file("pw_fails_complexity")
        if complexity:
            failures["Complexity Requirements"] = len(complexity) if isinstance(complexity, dict) else 0

        # Blank passwords
        blank = self._load_json_file("pw_fails_blank")
        if blank:
            failures["Blank Passwords"] = len(blank) if isinstance(blank, list) else 0

        # Max age failures
        max_age = self._load_json_file("pw_fails_max_age")
        if max_age:
            failures["Password Age"] = len(max_age) if isinstance(max_age, dict) else 0

        # LM hashes
        lm_hashes = self._load_json_file("pw_lm_hashes")
        if lm_hashes:
            failures["Legacy LM Hashes"] = len(lm_hashes) if isinstance(lm_hashes, list) else 0

        return failures

    def _derive_critical_findings(self) -> List[str]:
        """Generate critical findings from analysis data."""
        findings = []

        # Get stats
        stats = self._load_json_file("cracking_stats_table")
        stats_dict = {}
        if stats and isinstance(stats, list):
            for item in stats:
                if isinstance(item, dict):
                    key = item.get("key", "").strip().rstrip(":")
                    stats_dict[key] = item.get("value")

        # Check crack rate
        crack_pct = stats_dict.get("Percent of Accounts Cracked", "0%")
        if isinstance(crack_pct, str):
            crack_pct = crack_pct.replace("%", "")
        try:
            crack_rate = float(crack_pct)
            if crack_rate > 50:
                findings.append(f"CRITICAL: {crack_rate:.0f}% of passwords were cracked")
            elif crack_rate > 30:
                findings.append(f"HIGH: {crack_rate:.0f}% of passwords were cracked")
        except (ValueError, TypeError):
            pass

        # Check blank passwords
        blank = self._load_json_file("pw_fails_blank")
        if blank and len(blank) > 0:
            findings.append(f"CRITICAL: {len(blank)} accounts have blank passwords")

        # Check LM hashes
        lm_hashes = self._load_json_file("pw_lm_hashes")
        if lm_hashes and len(lm_hashes) > 0:
            findings.append(f"HIGH: {len(lm_hashes)} accounts have legacy LM hashes stored")

        # Check password reuse
        reuse = self._load_json_file("pw_reuse_table")
        if reuse and isinstance(reuse, list):
            high_reuse = [r for r in reuse if isinstance(r, list) and len(r) > 1 and r[1] > 5]
            if high_reuse:
                findings.append(f"HIGH: {len(high_reuse)} passwords are shared by more than 5 accounts")

        # Check bad practices
        bad = self._load_json_file("pw_bad_practices")
        if bad and isinstance(bad, dict):
            total_bad = sum(
                cat.get("count", 0) if isinstance(cat, dict) else 0
                for cat in bad.values()
            )
            if total_bad > 100:
                findings.append(f"MEDIUM: {total_bad} passwords follow known weak patterns")

        return findings

    def _derive_key_findings(self) -> List[str]:
        """Generate key findings for recommendations section."""
        findings = self._derive_critical_findings()

        # Add pattern-based findings
        bad = self._load_json_file("pw_bad_practices")
        if bad and isinstance(bad, dict):
            for category, data in bad.items():
                if isinstance(data, dict) and data.get("count", 0) > 20:
                    findings.append(f"{category}: {data['count']} passwords")

        return findings[:15]  # Limit to top 15 findings

    def _derive_worst_practices(self) -> List[str]:
        """Extract worst password practices with examples."""
        practices = []
        bad = self._load_json_file("pw_bad_practices")

        if bad and isinstance(bad, dict):
            # Sort by count descending
            sorted_cats = sorted(
                bad.items(),
                key=lambda x: x[1].get("count", 0) if isinstance(x[1], dict) else 0,
                reverse=True
            )

            for category, data in sorted_cats[:10]:
                if isinstance(data, dict):
                    count = data.get("count", 0)
                    examples = data.get("examples", {})
                    if isinstance(examples, dict):
                        top_examples = list(examples.keys())[:3]
                        practices.append(f"{category} ({count}): {', '.join(top_examples)}")

        return practices

    def _parse_stats_table(self) -> Dict[str, Any]:
        """Convert cracking_stats_table array to dictionary."""
        stats = self._load_json_file("cracking_stats_table")
        result = {}

        if stats and isinstance(stats, list):
            for item in stats:
                if isinstance(item, dict):
                    key = item.get("key", "").strip().rstrip(": ")
                    result[key] = item.get("value")

        return result

    def _derive_raw_data_summary(self) -> str:
        """
        Generate a summary of all available raw JSON data for the full report appendix.
        """
        lines = []

        # Stats summary
        stats = self._parse_stats_table()
        if stats:
            lines.append("=== Cracking Statistics ===")
            for key, value in stats.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

        # Password length distribution
        account_data = self._load_json_file("account_data")
        if account_data:
            lengths = {}
            for acc in account_data.values():
                pw = acc.get("cracked_pw", "")
                if pw:
                    length = len(pw)
                    lengths[length] = lengths.get(length, 0) + 1

            if lengths:
                lines.append("=== Password Length Distribution ===")
                for length in sorted(lengths.keys()):
                    lines.append(f"  {length} chars: {lengths[length]} passwords")
                lines.append("")

        # Character class analysis
        if account_data:
            char_classes = {
                "lowercase_only": 0,
                "uppercase_only": 0,
                "digits_only": 0,
                "mixed_case": 0,
                "alphanumeric": 0,
                "with_symbols": 0
            }
            for acc in account_data.values():
                pw = acc.get("cracked_pw", "")
                if pw:
                    has_lower = any(c.islower() for c in pw)
                    has_upper = any(c.isupper() for c in pw)
                    has_digit = any(c.isdigit() for c in pw)
                    has_symbol = any(not c.isalnum() for c in pw)

                    if has_symbol:
                        char_classes["with_symbols"] += 1
                    elif has_lower and has_upper and has_digit:
                        char_classes["alphanumeric"] += 1
                    elif has_lower and has_upper:
                        char_classes["mixed_case"] += 1
                    elif has_lower:
                        char_classes["lowercase_only"] += 1
                    elif has_upper:
                        char_classes["uppercase_only"] += 1
                    elif has_digit:
                        char_classes["digits_only"] += 1

            lines.append("=== Character Class Distribution ===")
            for cls, count in char_classes.items():
                if count > 0:
                    lines.append(f"  {cls.replace('_', ' ').title()}: {count}")
            lines.append("")

        # Bad practices summary
        bad = self._load_json_file("pw_bad_practices")
        if bad and isinstance(bad, dict):
            lines.append("=== Pattern Frequency ===")
            sorted_cats = sorted(
                bad.items(),
                key=lambda x: x[1].get("count", 0) if isinstance(x[1], dict) else 0,
                reverse=True
            )
            for cat, data in sorted_cats:
                if isinstance(data, dict):
                    count = data.get("count", 0)
                    if count > 0:
                        lines.append(f"  {cat}: {count}")
            lines.append("")

        # Top reused passwords
        reuse = self._load_json_file("pw_reuse_table")
        if reuse and isinstance(reuse, list):
            high_reuse = [r for r in reuse if isinstance(r, list) and len(r) > 1 and r[1] > 2]
            if high_reuse:
                lines.append(f"=== Password Reuse (>{2} accounts) ===")
                lines.append(f"  {len(high_reuse)} passwords shared across multiple accounts")
                lines.append("")

        # Policy failures summary
        failures = self._derive_policy_failures()
        if failures:
            lines.append("=== Policy Violations ===")
            for policy, count in failures.items():
                lines.append(f"  {policy}: {count}")
            lines.append("")

        return "\n".join(lines) if lines else "No raw data available"

    def load_section_data(
        self,
        section_id: str,
        session_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Load all required data for a specific AI report section.

        Args:
            section_id: The section identifier (e.g., "weak-habits")
            session_data: Optional Flask session data for session-based sources

        Returns:
            Dictionary with all data needed for the section's prompt
        """
        section_config = AI_REPORT_SECTIONS.get(section_id)
        if not section_config:
            return {}

        data_sources = section_config.get("data_sources", {})
        result = {}

        for var_name, source in data_sources.items():
            if source.startswith("file:"):
                filename = source.replace("file:", "")
                data = self._load_json_file(filename)

                # Transform certain file formats for prompt compatibility
                if filename == "pw_substrings" and isinstance(data, list):
                    # Already in correct format
                    result[var_name] = data
                elif filename == "pw_dict_words" and isinstance(data, dict):
                    # Convert to list format for prompts
                    result[var_name] = [
                        {"word": word, "count": count}
                        for word, count in data.items()
                    ]
                elif filename == "cracking_stats_table":
                    # Parse to dictionary format
                    result[var_name] = self._parse_stats_table()
                else:
                    result[var_name] = data

            elif source.startswith("derived:"):
                func_name = source.replace("derived:", "")
                # Original derive functions
                if func_name == "password_samples":
                    result[var_name] = self._derive_password_samples()
                elif func_name == "company_terms":
                    result[var_name] = self._derive_company_terms()
                elif func_name == "policy_failures":
                    result[var_name] = self._derive_policy_failures()
                elif func_name == "critical_findings":
                    result[var_name] = self._derive_critical_findings()
                elif func_name == "key_findings":
                    result[var_name] = self._derive_key_findings()
                elif func_name == "worst_practices":
                    result[var_name] = self._derive_worst_practices()
                # Raw data derive functions for AI analysis
                elif func_name == "all_cracked_passwords":
                    result[var_name] = self._derive_all_cracked_passwords()
                elif func_name == "account_password_pairs":
                    result[var_name] = self._derive_account_password_pairs()
                elif func_name == "all_account_names":
                    result[var_name] = self._derive_all_account_names()
                elif func_name == "password_reuse_details":
                    result[var_name] = self._derive_password_reuse_details()
                elif func_name == "organizational_context":
                    result[var_name] = self._derive_organizational_context()
                elif func_name == "total_account_count":
                    result[var_name] = self._derive_total_account_count()
                elif func_name == "cracked_account_count":
                    result[var_name] = self._derive_cracked_account_count()
                elif func_name == "raw_data_summary":
                    result[var_name] = self._derive_raw_data_summary()

            elif source.startswith("session:"):
                key = source.replace("session:", "")
                if session_data and key in session_data:
                    result[var_name] = session_data[key]
                else:
                    # Provide sensible defaults for policy
                    if key == "analysis_options":
                        result[var_name] = {
                            "min_length": 12,
                            "complexity": "3 of 4 character types",
                            "max_age": 90
                        }

        return result

    def has_analysis_data(self) -> bool:
        """Check if analysis data files exist."""
        required_files = ["pw_top_passwords", "cracking_stats_table", "account_data"]
        for filename in required_files:
            filepath = os.path.join(self.data_dir, f"{filename}.json")
            if not os.path.exists(filepath):
                return False
        return True

    def get_data_summary(self) -> Dict[str, Any]:
        """Get a summary of available analysis data for the UI."""
        summary = {
            "has_data": self.has_analysis_data(),
            "files_found": [],
            "files_missing": [],
            "stats": {}
        }

        all_files = [
            "account_data", "cracking_stats_table", "pw_top_passwords",
            "pw_substrings", "pw_dict_words", "pw_bad_practices",
            "pw_length_distribution", "pw_fails_min_length",
            "pw_fails_complexity", "pw_fails_blank", "pw_fails_max_age",
            "pw_lm_hashes", "pw_reuse_table"
        ]

        for filename in all_files:
            filepath = os.path.join(self.data_dir, f"{filename}.json")
            if os.path.exists(filepath):
                summary["files_found"].append(filename)
            else:
                summary["files_missing"].append(filename)

        # Get basic stats if available
        if summary["has_data"]:
            stats = self._parse_stats_table()
            summary["stats"] = {
                "total_accounts": stats.get("Total Accounts Analyzed", 0),
                "cracked_accounts": stats.get("Cracked Accounts", 0),
                "crack_percent": stats.get("Percent of Accounts Cracked", "0%")
            }

        return summary


def get_ai_data_loader(data_dir: str = "data") -> AIReportDataLoader:
    """Factory function to create an AIReportDataLoader instance."""
    return AIReportDataLoader(data_dir)


# =============================================================================
# Utility Functions
# =============================================================================

def test_ollama_connection(host: Optional[str] = None, server_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Test connection to Ollama server and return status info.

    Args:
        host: Ollama server URL (uses env var if not provided)
        server_id: Server ID to test (alternative to host)

    Returns:
        Dictionary with connection status and available models
    """
    config = get_ollama_config(server_id)
    if host:
        config.host = host
        config.enabled = True

    client = OllamaClient(config)

    result = {
        "host": config.host,
        "enabled": config.enabled,
        "reachable": False,
        "available_models": [],
        "error": None
    }

    try:
        response = requests.get(f"{config.host}/api/tags", timeout=5)
        if response.status_code == 200:
            result["reachable"] = True
            data = response.json()
            result["available_models"] = [m["name"] for m in data.get("models", [])]
        else:
            result["error"] = f"HTTP {response.status_code}"
    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def test_all_servers() -> Dict[str, Any]:
    """
    Test connection to all configured Ollama servers.

    Returns:
        Dictionary with status for each server
    """
    servers = get_ollama_servers()
    results = {
        "servers": [],
        "any_available": False
    }

    for server in servers:
        status = test_ollama_connection(host=server.host)
        server_info = {
            "id": server.id,
            "name": server.name,
            "host": server.host,
            "description": server.description,
            "hardware": server.hardware,
            "reachable": status["reachable"],
            "available_models": status["available_models"],
            "error": status.get("error")
        }
        results["servers"].append(server_info)
        if status["reachable"]:
            results["any_available"] = True

    return results


def quick_generate(prompt: str, host: Optional[str] = None) -> Optional[str]:
    """
    Quick one-off generation without full client setup.

    Args:
        prompt: The prompt to send
        host: Ollama server URL

    Returns:
        Generated text or None
    """
    config = get_ollama_config()
    if host:
        config.host = host
        config.enabled = True

    client = OllamaClient(config)
    return client.generate(prompt)


# Popular models from Ollama library - curated list for UI selection
# recommended_for: list of analysis types this model excels at
POPULAR_OLLAMA_MODELS = [
    {
        "name": "llama3.2",
        "description": "Meta's latest Llama model (3B, 1B)",
        "sizes": ["3b", "1b"],
        "recommended_for": ["quick-analysis"],
        "notes": "Fast, good for interactive testing"
    },
    {
        "name": "llama3.1",
        "description": "Meta's Llama 3.1 (8B, 70B, 405B)",
        "sizes": ["8b", "70b", "405b"],
        "recommended_for": ["executive-summary", "pattern-analysis", "report-writing"],
        "notes": "Best balance of quality and speed. 70B recommended for reports."
    },
    {
        "name": "deepseek-r1",
        "description": "DeepSeek reasoning model",
        "sizes": ["7b", "14b", "32b", "70b", "671b"],
        "recommended_for": ["attack-strategy", "semantic-clustering", "technical-analysis"],
        "notes": "Excellent reasoning. Best for complex analysis tasks."
    },
    {
        "name": "qwen2.5",
        "description": "Alibaba's Qwen 2.5",
        "sizes": ["0.5b", "1.5b", "3b", "7b", "14b", "32b", "72b"],
        "recommended_for": ["pattern-analysis", "quick-analysis"],
        "notes": "Good general purpose model"
    },
    {
        "name": "qwen2.5-coder",
        "description": "Qwen 2.5 optimized for code",
        "sizes": ["0.5b", "1.5b", "3b", "7b", "14b", "32b"],
        "recommended_for": ["attack-strategy"],
        "notes": "Good for generating hashcat commands and rules"
    },
    {
        "name": "mistral",
        "description": "Mistral AI 7B model",
        "sizes": ["7b"],
        "recommended_for": ["quick-analysis"],
        "notes": "Fast and efficient for simple tasks"
    },
    {
        "name": "mixtral",
        "description": "Mistral's MoE model",
        "sizes": ["8x7b", "8x22b"],
        "recommended_for": ["executive-summary", "pattern-analysis"],
        "notes": "Good quality with reasonable speed"
    },
    {
        "name": "gemma2",
        "description": "Google's Gemma 2",
        "sizes": ["2b", "9b", "27b"],
        "recommended_for": ["quick-analysis", "pattern-analysis"],
        "notes": "Efficient, good for structured output"
    },
    {
        "name": "phi4",
        "description": "Microsoft Phi-4",
        "sizes": ["14b"],
        "recommended_for": ["pattern-analysis", "semantic-clustering"],
        "notes": "Strong reasoning for its size"
    },
    {
        "name": "codellama",
        "description": "Meta's code-focused Llama",
        "sizes": ["7b", "13b", "34b", "70b"],
        "recommended_for": ["attack-strategy"],
        "notes": "Best for generating attack commands and scripts"
    },
    {
        "name": "llava",
        "description": "Vision-language model",
        "sizes": ["7b", "13b", "34b"],
        "recommended_for": [],
        "notes": "Not recommended for text-only password analysis"
    },
    {
        "name": "nomic-embed-text",
        "description": "Text embedding model",
        "sizes": [],
        "recommended_for": [],
        "notes": "Embedding model - not for text generation"
    },
    {
        "name": "mxbai-embed-large",
        "description": "Mixedbread embedding model",
        "sizes": [],
        "recommended_for": [],
        "notes": "Embedding model - not for text generation"
    },
]


# =============================================================================
# Analysis Presets
# =============================================================================
# Pre-configured settings for different analysis types

ANALYSIS_PRESETS = {
    "executive-summary": {
        "name": "Executive Summary",
        "description": "Generate polished summaries for C-level executives",
        "recommended_models": ["llama3.1:70b", "llama3.1:405b", "gpt-oss:120b", "mixtral:8x22b"],
        "temperature": 0.7,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "EXECUTIVE_SUMMARY_PROMPT",
        "tips": "Use larger models for better prose quality. Lower temperature for consistency."
    },
    "pattern-analysis": {
        "name": "Pattern Analysis",
        "description": "Analyze password patterns and explain security implications",
        "recommended_models": ["llama3.1:70b", "deepseek-r1:70b", "phi4:14b"],
        "temperature": 0.5,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "PATTERN_DESCRIPTION_PROMPT",
        "tips": "Lower temperature helps maintain consistent analysis structure."
    },
    "semantic-clustering": {
        "name": "Semantic Clustering",
        "description": "Categorize passwords by meaning and theme",
        "recommended_models": ["deepseek-r1:70b", "llama3.1:70b", "phi4:14b"],
        "temperature": 0.3,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "SEMANTIC_CLUSTERING_PROMPT",
        "tips": "Low temperature ensures consistent JSON output. DeepSeek excels at categorization."
    },
    "attack-strategy": {
        "name": "Attack Strategy",
        "description": "Generate hashcat commands and attack recommendations",
        "recommended_models": ["deepseek-r1:70b", "codellama:70b", "qwen2.5-coder:32b"],
        "temperature": 0.5,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": "ATTACK_STRATEGY_PROMPT",
        "tips": "Reasoning models produce better strategic recommendations."
    },
    "quick-analysis": {
        "name": "Quick Analysis",
        "description": "Fast, interactive password analysis for testing",
        "recommended_models": ["llama3.1:8b", "llama3.2:3b", "mistral:7b", "gemma2:9b"],
        "temperature": 0.6,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": None,
        "tips": "Use smaller models for faster iteration during testing."
    },
    "report-writing": {
        "name": "Report Writing",
        "description": "Generate professional report sections",
        "recommended_models": ["llama3.1:70b", "llama3.1:405b", "gpt-oss:120b"],
        "temperature": 0.6,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": None,
        "tips": "Larger models produce more polished, professional prose."
    },
    "technical-analysis": {
        "name": "Technical Analysis",
        "description": "Deep technical analysis of password weaknesses",
        "recommended_models": ["deepseek-r1:70b", "deepseek-r1:671b", "llama3.1:405b"],
        "temperature": 0.4,
        "system_prompt_key": "SYSTEM_PROMPT",
        "user_prompt_template": None,
        "tips": "DeepSeek's reasoning ability excels at technical deep-dives."
    }
}


def get_analysis_presets() -> Dict[str, Any]:
    """Get all analysis preset configurations."""
    return ANALYSIS_PRESETS


def get_preset_for_task(task_type: str) -> Optional[Dict[str, Any]]:
    """Get the preset configuration for a specific task type."""
    return ANALYSIS_PRESETS.get(task_type)


def get_available_library_models() -> List[Dict[str, Any]]:
    """
    Get list of popular models available to pull from Ollama library.

    Returns:
        List of model dictionaries with name, description, and sizes
    """
    return POPULAR_OLLAMA_MODELS


def pull_model(model_name: str, host: Optional[str] = None) -> Dict[str, Any]:
    """
    Pull (download) a model from Ollama library.

    Args:
        model_name: Name of the model to pull (e.g., "llama3.1:70b")
        host: Ollama server URL (uses env var if not provided)

    Returns:
        Dictionary with pull status and any error message
    """
    config = get_ollama_config()
    if host:
        config.host = host
        config.enabled = True

    if not config.enabled:
        return {"success": False, "error": "Ollama integration is not enabled"}

    result = {
        "success": False,
        "model": model_name,
        "status": "",
        "error": None
    }

    try:
        # Ollama pull API - uses streaming by default
        response = requests.post(
            f"{config.host}/api/pull",
            json={"name": model_name, "stream": False},
            timeout=600  # 10 minutes for large models
        )

        if response.status_code == 200:
            data = response.json()
            result["success"] = True
            result["status"] = data.get("status", "success")
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text}"

    except requests.Timeout:
        result["error"] = "Request timed out - model may still be downloading in background"
    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def delete_model(model_name: str, host: Optional[str] = None) -> Dict[str, Any]:
    """
    Delete a model from the Ollama server.

    Args:
        model_name: Name of the model to delete
        host: Ollama server URL (uses env var if not provided)

    Returns:
        Dictionary with deletion status
    """
    config = get_ollama_config()
    if host:
        config.host = host
        config.enabled = True

    if not config.enabled:
        return {"success": False, "error": "Ollama integration is not enabled"}

    result = {
        "success": False,
        "model": model_name,
        "error": None
    }

    try:
        response = requests.delete(
            f"{config.host}/api/delete",
            json={"name": model_name},
            timeout=30
        )

        if response.status_code == 200:
            result["success"] = True
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text}"

    except requests.RequestException as e:
        result["error"] = str(e)

    return result


def get_model_info(model_name: str, host: Optional[str] = None) -> Dict[str, Any]:
    """
    Get detailed information about a model.

    Args:
        model_name: Name of the model
        host: Ollama server URL

    Returns:
        Dictionary with model details or error
    """
    config = get_ollama_config()
    if host:
        config.host = host
        config.enabled = True

    if not config.enabled:
        return {"error": "Ollama integration is not enabled"}

    try:
        response = requests.post(
            f"{config.host}/api/show",
            json={"name": model_name},
            timeout=10
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}

    except requests.RequestException as e:
        return {"error": str(e)}
