"""
Job Template and Sequence Management for HM1K

Provides predefined hashcat job templates and the ability to create
custom templates and sequences (ordered groups of jobs).
"""

import json
import os
import logging
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)


@dataclass
class JobTemplate:
    """A hashcat job template with predefined settings."""
    id: str
    name: str
    description: str
    category: str  # e.g., "Wordlist", "Rules", "Brute Force", "Hybrid", "Hash-Specific"
    hash_mode: Optional[int]  # hashcat -m value, None = user selects at runtime (hash-agnostic)
    attack_mode: int = 0  # hashcat -a value (0=wordlist, 1=combo, 3=brute, 6=hybrid, 7=hybrid)

    # Raw hashcat arguments (new simplified format - takes precedence over individual fields)
    hashcat_args: Optional[str] = None  # e.g., "-a 0 /opt/wordlists/rockyou.txt -r best64.rule"

    # Attack-specific settings (legacy format, used if hashcat_args is None)
    wordlist: Optional[str] = None  # Path to wordlist for -a 0
    rules: Optional[list[str]] = None  # Rule files for -r
    mask: Optional[str] = None  # Mask for -a 3
    increment: bool = False  # Use --increment
    increment_min: Optional[int] = None
    increment_max: Optional[int] = None
    custom_charset_1: Optional[str] = None  # -1 custom charset

    # Options
    optimized_kernels: bool = False  # -O flag
    workload_profile: int = 3  # -w value (1-4)

    # Metadata
    is_builtin: bool = False
    created_at: Optional[str] = None
    estimated_time: Optional[str] = None  # Human-readable estimate

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "hash_mode": self.hash_mode,
            "attack_mode": self.attack_mode,
            "hashcat_args": self.hashcat_args,
            "wordlist": self.wordlist,
            "rules": self.rules,
            "mask": self.mask,
            "increment": self.increment,
            "increment_min": self.increment_min,
            "increment_max": self.increment_max,
            "custom_charset_1": self.custom_charset_1,
            "optimized_kernels": self.optimized_kernels,
            "workload_profile": self.workload_profile,
            "is_builtin": self.is_builtin,
            "created_at": self.created_at,
            "estimated_time": self.estimated_time,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JobTemplate":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            category=data["category"],
            hash_mode=data.get("hash_mode"),
            attack_mode=data.get("attack_mode", 0),
            hashcat_args=data.get("hashcat_args"),
            wordlist=data.get("wordlist"),
            rules=data.get("rules"),
            mask=data.get("mask"),
            increment=data.get("increment", False),
            increment_min=data.get("increment_min"),
            increment_max=data.get("increment_max"),
            custom_charset_1=data.get("custom_charset_1"),
            optimized_kernels=data.get("optimized_kernels", False),
            workload_profile=data.get("workload_profile", 3),
            is_builtin=data.get("is_builtin", False),
            created_at=data.get("created_at"),
            estimated_time=data.get("estimated_time"),
        )

    def build_hashcat_args(self, hash_mode_override: Optional[int] = None) -> list[str]:
        """Build hashcat command arguments from template settings.

        Args:
            hash_mode_override: Hash mode to use if template is hash-agnostic (hash_mode is None)
        """
        import shlex

        effective_hash_mode = hash_mode_override if self.hash_mode is None else self.hash_mode
        if effective_hash_mode is None:
            raise ValueError("Hash mode must be specified for hash-agnostic templates")

        # New simplified format: use hashcat_args directly if set
        if self.hashcat_args:
            args = ["-m", str(effective_hash_mode)]
            # Parse the raw args string properly (handles quoted paths, etc.)
            args.extend(shlex.split(self.hashcat_args))
            return args

        # Legacy format: build from individual fields
        args = [
            "-m", str(effective_hash_mode),
            "-a", str(self.attack_mode),
        ]

        # Custom charset
        if self.custom_charset_1:
            args.extend(["-1", self.custom_charset_1])

        # Attack mode specific
        if self.attack_mode == 0:  # Wordlist
            if self.wordlist:
                args.append(self.wordlist)
            if self.rules:
                for rule in self.rules:
                    args.extend(["-r", rule])
        elif self.attack_mode == 3:  # Brute force
            if self.mask:
                args.append(self.mask)
            if self.increment:
                args.append("--increment")
                if self.increment_min is not None:
                    args.extend(["--increment-min", str(self.increment_min)])
                if self.increment_max is not None:
                    args.extend(["--increment-max", str(self.increment_max)])

        # Options
        if self.optimized_kernels:
            args.append("-O")
        if self.workload_profile != 3:
            args.extend(["-w", str(self.workload_profile)])

        return args


@dataclass
class JobSequenceStep:
    """A single step in a job sequence."""
    template_id: str
    order: int
    stop_on_success: bool = False  # Stop sequence if this step cracks 100%
    min_crack_rate: Optional[float] = None  # Only continue if crack rate below this


@dataclass
class JobSequence:
    """An ordered sequence of job templates to run."""
    id: str
    name: str
    description: str
    steps: list[JobSequenceStep] = field(default_factory=list)
    is_builtin: bool = False
    created_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "steps": [
                {
                    "template_id": s.template_id,
                    "order": s.order,
                    "stop_on_success": s.stop_on_success,
                    "min_crack_rate": s.min_crack_rate,
                }
                for s in self.steps
            ],
            "is_builtin": self.is_builtin,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JobSequence":
        steps = [
            JobSequenceStep(
                template_id=s["template_id"],
                order=s["order"],
                stop_on_success=s.get("stop_on_success", False),
                min_crack_rate=s.get("min_crack_rate"),
            )
            for s in data.get("steps", [])
        ]
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            steps=sorted(steps, key=lambda x: x.order),
            is_builtin=data.get("is_builtin", False),
            created_at=data.get("created_at"),
        )


# Built-in templates
BUILTIN_TEMPLATES: list[JobTemplate] = [
    # ==========================================================================
    # Hash-Agnostic Templates (work with any hash type)
    # ==========================================================================

    # Wordlist Attacks
    JobTemplate(
        id="wordlist-rockyou",
        name="Wordlist (RockYou)",
        description="Dictionary attack using rockyou.txt - works with any hash type",
        category="Wordlist",
        hash_mode=None,  # User selects hash type
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        is_builtin=True,
        estimated_time="Fast",
    ),
    JobTemplate(
        id="wordlist-custom",
        name="Wordlist (Custom Path)",
        description="Dictionary attack with user-specified wordlist path",
        category="Wordlist",
        hash_mode=None,
        attack_mode=0,
        wordlist="",  # User provides path
        is_builtin=True,
        estimated_time="Varies",
    ),

    # Rule-based Attacks
    JobTemplate(
        id="rules-best64",
        name="Wordlist + Best64 Rules",
        description="RockYou wordlist with best64 rule mutations (64x wordlist size)",
        category="Rules",
        hash_mode=None,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        rules=["/opt/hashcat/rules/best64.rule"],
        is_builtin=True,
        estimated_time="Medium",
    ),
    JobTemplate(
        id="rules-dive",
        name="Wordlist + Dive Rules",
        description="RockYou wordlist with dive.rule for comprehensive mutations",
        category="Rules",
        hash_mode=None,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        rules=["/opt/hashcat/rules/dive.rule"],
        is_builtin=True,
        estimated_time="Long",
    ),
    JobTemplate(
        id="rules-oneruletorulethemall",
        name="Wordlist + OneRuleToRuleThemAll",
        description="RockYou with OneRuleToRuleThemAll - highly effective rule set",
        category="Rules",
        hash_mode=None,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        rules=["/opt/hashcat/rules/OneRuleToRuleThemAll.rule"],
        is_builtin=True,
        estimated_time="Long",
    ),

    # Brute Force Attacks
    JobTemplate(
        id="brute-1-4",
        name="Brute Force (1-4 chars)",
        description="All printable ASCII characters, 1-4 character length",
        category="Brute Force",
        hash_mode=None,
        attack_mode=3,
        mask="?a?a?a?a",
        increment=True,
        increment_min=1,
        increment_max=4,
        optimized_kernels=True,
        is_builtin=True,
        estimated_time="Fast",
    ),
    JobTemplate(
        id="brute-5",
        name="Brute Force (5 chars)",
        description="All printable ASCII characters, exactly 5 characters",
        category="Brute Force",
        hash_mode=None,
        attack_mode=3,
        mask="?a?a?a?a?a",
        optimized_kernels=True,
        is_builtin=True,
        estimated_time="Medium",
    ),
    JobTemplate(
        id="brute-6",
        name="Brute Force (6 chars)",
        description="All printable ASCII characters, exactly 6 characters",
        category="Brute Force",
        hash_mode=None,
        attack_mode=3,
        mask="?a?a?a?a?a?a",
        optimized_kernels=True,
        is_builtin=True,
        estimated_time="Long",
    ),
    JobTemplate(
        id="brute-digits-6",
        name="Numeric PIN (1-6 digits)",
        description="Numeric-only brute force, 1-6 digits (e.g., PINs)",
        category="Brute Force",
        hash_mode=None,
        attack_mode=3,
        mask="?d?d?d?d?d?d",
        increment=True,
        increment_min=1,
        increment_max=6,
        optimized_kernels=True,
        is_builtin=True,
        estimated_time="Very Fast",
    ),
    JobTemplate(
        id="brute-digits-8",
        name="Numeric PIN (1-8 digits)",
        description="Numeric-only brute force, 1-8 digits",
        category="Brute Force",
        hash_mode=None,
        attack_mode=3,
        mask="?d?d?d?d?d?d?d?d",
        increment=True,
        increment_min=1,
        increment_max=8,
        optimized_kernels=True,
        is_builtin=True,
        estimated_time="Fast",
    ),

    # Mask/Pattern Attacks
    JobTemplate(
        id="mask-word-digits",
        name="Pattern: Word + 4 Digits",
        description="Capitalized word followed by 4 digits (e.g., Password1234)",
        category="Mask",
        hash_mode=None,
        attack_mode=3,
        mask="?u?l?l?l?l?l?d?d?d?d",
        is_builtin=True,
        estimated_time="Medium",
    ),
    JobTemplate(
        id="mask-word-year",
        name="Pattern: Word + Year",
        description="Word followed by year 19xx or 20xx (e.g., Password2024)",
        category="Mask",
        hash_mode=None,
        attack_mode=3,
        custom_charset_1="12",
        mask="?u?l?l?l?l?l?l?19?d?d",  # This is a simplified version
        is_builtin=True,
        estimated_time="Medium",
    ),
    JobTemplate(
        id="mask-lowercase-digits",
        name="Pattern: Lowercase + Digits",
        description="6 lowercase letters followed by 2 digits",
        category="Mask",
        hash_mode=None,
        attack_mode=3,
        mask="?l?l?l?l?l?l?d?d",
        is_builtin=True,
        estimated_time="Medium",
    ),

    # ==========================================================================
    # Hash-Specific Templates (require specific hash type)
    # ==========================================================================

    # LM Hash (requires uppercase charset)
    JobTemplate(
        id="lm-brute-full",
        name="LM Brute Force (1-7 chars)",
        description="LM hash halves - uppercase + digits + symbols only",
        category="Hash-Specific",
        hash_mode=3000,
        attack_mode=3,
        custom_charset_1="?u?d?s",
        mask="?1?1?1?1?1?1?1",
        increment=True,
        increment_min=1,
        increment_max=7,
        is_builtin=True,
        estimated_time="Medium",
    ),

    # Kerberos (commonly targeted with specific wordlists)
    JobTemplate(
        id="kerberos-tgs-wordlist",
        name="Kerberos TGS-REP (Kerberoasting)",
        description="Kerberoasting attack - service account passwords",
        category="Hash-Specific",
        hash_mode=13100,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        is_builtin=True,
        estimated_time="Medium",
    ),
    JobTemplate(
        id="kerberos-asrep-wordlist",
        name="Kerberos AS-REP (AS-REP Roasting)",
        description="AS-REP roasting - accounts without pre-auth",
        category="Hash-Specific",
        hash_mode=18200,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        is_builtin=True,
        estimated_time="Medium",
    ),

    # NetNTLM (network captures)
    JobTemplate(
        id="netntlmv2-wordlist",
        name="NetNTLMv2 (Responder/Relay)",
        description="NetNTLMv2 from network captures - Responder, Relay attacks",
        category="Hash-Specific",
        hash_mode=5600,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        is_builtin=True,
        estimated_time="Medium",
    ),
    JobTemplate(
        id="netntlmv1-wordlist",
        name="NetNTLMv1 (Legacy)",
        description="NetNTLMv1 legacy protocol captures",
        category="Hash-Specific",
        hash_mode=5500,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        is_builtin=True,
        estimated_time="Medium",
    ),

    # Domain Cached Credentials
    JobTemplate(
        id="dcc2-wordlist",
        name="Domain Cached Credentials v2",
        description="MS Cache v2 / DCC2 - slow due to 10240 iterations",
        category="Hash-Specific",
        hash_mode=2100,
        attack_mode=0,
        wordlist="/opt/wordlists/rockyou.txt",
        is_builtin=True,
        estimated_time="Very Slow",
    ),
]


# Built-in sequences
BUILTIN_SEQUENCES: list[JobSequence] = [
    JobSequence(
        id="comprehensive-attack",
        name="Comprehensive Attack",
        description="Full attack sequence: wordlist → rules → brute force (works with any hash type)",
        steps=[
            JobSequenceStep(template_id="wordlist-rockyou", order=1),
            JobSequenceStep(template_id="rules-best64", order=2),
            JobSequenceStep(template_id="brute-1-4", order=3),
            JobSequenceStep(template_id="mask-word-digits", order=4),
            JobSequenceStep(template_id="brute-5", order=5, min_crack_rate=90.0),
        ],
        is_builtin=True,
    ),
    JobSequence(
        id="quick-attack",
        name="Quick Attack",
        description="Fast attack for common passwords (works with any hash type)",
        steps=[
            JobSequenceStep(template_id="wordlist-rockyou", order=1),
            JobSequenceStep(template_id="brute-1-4", order=2),
        ],
        is_builtin=True,
    ),
    JobSequence(
        id="thorough-wordlist",
        name="Thorough Wordlist Attack",
        description="Multiple rule sets for maximum wordlist coverage",
        steps=[
            JobSequenceStep(template_id="wordlist-rockyou", order=1),
            JobSequenceStep(template_id="rules-best64", order=2),
            JobSequenceStep(template_id="rules-dive", order=3),
            JobSequenceStep(template_id="rules-oneruletorulethemall", order=4),
        ],
        is_builtin=True,
    ),
    JobSequence(
        id="kerberos-full",
        name="Kerberos Full Attack",
        description="Complete Kerberoasting attack with wordlist and rules",
        steps=[
            JobSequenceStep(template_id="kerberos-tgs-wordlist", order=1),
            JobSequenceStep(template_id="rules-best64", order=2),
        ],
        is_builtin=True,
    ),
]


class JobTemplateManager:
    """Manages job templates and sequences."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.templates_dir = self.data_dir / "job_templates"
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        self.templates_file = self.templates_dir / "custom_templates.json"
        self.sequences_file = self.templates_dir / "custom_sequences.json"

        self._custom_templates: dict[str, JobTemplate] = {}
        self._custom_sequences: dict[str, JobSequence] = {}

        self._load_custom_data()

    def _load_custom_data(self) -> None:
        """Load custom templates and sequences from disk."""
        # Load custom templates
        if self.templates_file.exists():
            try:
                with open(self.templates_file, "r") as f:
                    data = json.load(f)
                    for t in data.get("templates", []):
                        template = JobTemplate.from_dict(t)
                        self._custom_templates[template.id] = template
                logger.info(f"Loaded {len(self._custom_templates)} custom templates")
            except Exception as e:
                logger.error(f"Error loading custom templates: {e}")

        # Load custom sequences
        if self.sequences_file.exists():
            try:
                with open(self.sequences_file, "r") as f:
                    data = json.load(f)
                    for s in data.get("sequences", []):
                        sequence = JobSequence.from_dict(s)
                        self._custom_sequences[sequence.id] = sequence
                logger.info(f"Loaded {len(self._custom_sequences)} custom sequences")
            except Exception as e:
                logger.error(f"Error loading custom sequences: {e}")

    def _save_custom_templates(self) -> None:
        """Save custom templates to disk."""
        data = {
            "templates": [t.to_dict() for t in self._custom_templates.values()]
        }
        with open(self.templates_file, "w") as f:
            json.dump(data, f, indent=2)

    def _save_custom_sequences(self) -> None:
        """Save custom sequences to disk."""
        data = {
            "sequences": [s.to_dict() for s in self._custom_sequences.values()]
        }
        with open(self.sequences_file, "w") as f:
            json.dump(data, f, indent=2)

    def get_all_templates(self) -> list[JobTemplate]:
        """Get all templates (builtin + custom)."""
        all_templates = list(BUILTIN_TEMPLATES)
        all_templates.extend(self._custom_templates.values())
        return all_templates

    def get_template(self, template_id: str) -> Optional[JobTemplate]:
        """Get a template by ID."""
        # Check builtin first
        for t in BUILTIN_TEMPLATES:
            if t.id == template_id:
                return t
        # Then custom
        return self._custom_templates.get(template_id)

    def create_template(self, template: JobTemplate) -> JobTemplate:
        """Create a new custom template."""
        if not template.id:
            template.id = f"custom-{uuid.uuid4().hex[:8]}"
        template.created_at = datetime.now().isoformat()
        template.is_builtin = False

        self._custom_templates[template.id] = template
        self._save_custom_templates()
        return template

    def update_template(self, template: JobTemplate) -> Optional[JobTemplate]:
        """Update an existing custom template."""
        if template.id not in self._custom_templates:
            return None
        if self._custom_templates[template.id].is_builtin:
            return None  # Can't update builtin

        self._custom_templates[template.id] = template
        self._save_custom_templates()
        return template

    def delete_template(self, template_id: str) -> bool:
        """Delete a custom template."""
        if template_id not in self._custom_templates:
            return False
        if self._custom_templates[template_id].is_builtin:
            return False

        del self._custom_templates[template_id]
        self._save_custom_templates()
        return True

    def get_all_sequences(self) -> list[JobSequence]:
        """Get all sequences (builtin + custom)."""
        all_sequences = list(BUILTIN_SEQUENCES)
        all_sequences.extend(self._custom_sequences.values())
        return all_sequences

    def get_sequence(self, sequence_id: str) -> Optional[JobSequence]:
        """Get a sequence by ID."""
        for s in BUILTIN_SEQUENCES:
            if s.id == sequence_id:
                return s
        return self._custom_sequences.get(sequence_id)

    def create_sequence(self, sequence: JobSequence) -> JobSequence:
        """Create a new custom sequence."""
        if not sequence.id:
            sequence.id = f"seq-{uuid.uuid4().hex[:8]}"
        sequence.created_at = datetime.now().isoformat()
        sequence.is_builtin = False

        self._custom_sequences[sequence.id] = sequence
        self._save_custom_sequences()
        return sequence

    def update_sequence(self, sequence: JobSequence) -> Optional[JobSequence]:
        """Update an existing custom sequence."""
        if sequence.id not in self._custom_sequences:
            return None
        if self._custom_sequences[sequence.id].is_builtin:
            return None

        self._custom_sequences[sequence.id] = sequence
        self._save_custom_sequences()
        return sequence

    def delete_sequence(self, sequence_id: str) -> bool:
        """Delete a custom sequence."""
        if sequence_id not in self._custom_sequences:
            return False
        if self._custom_sequences[sequence_id].is_builtin:
            return False

        del self._custom_sequences[sequence_id]
        self._save_custom_sequences()
        return True

    def get_templates_by_category(self) -> dict[str, list[JobTemplate]]:
        """Get all templates grouped by category."""
        by_category: dict[str, list[JobTemplate]] = {}
        for template in self.get_all_templates():
            if template.category not in by_category:
                by_category[template.category] = []
            by_category[template.category].append(template)
        return by_category

    def get_sequence_with_templates(self, sequence_id: str) -> Optional[dict]:
        """Get a sequence with its template details expanded."""
        sequence = self.get_sequence(sequence_id)
        if not sequence:
            return None

        steps_with_templates = []
        for step in sequence.steps:
            template = self.get_template(step.template_id)
            steps_with_templates.append({
                "order": step.order,
                "template_id": step.template_id,
                "template": template.to_dict() if template else None,
                "stop_on_success": step.stop_on_success,
                "min_crack_rate": step.min_crack_rate,
            })

        return {
            **sequence.to_dict(),
            "steps_expanded": steps_with_templates,
        }


# Hash mode reference for UI
HASH_MODES = {
    0: {"name": "MD5", "category": "Generic"},
    100: {"name": "SHA1", "category": "Generic"},
    1000: {"name": "NTLM", "category": "Windows"},
    1400: {"name": "SHA256", "category": "Generic"},
    1700: {"name": "SHA512", "category": "Generic"},
    2100: {"name": "Domain Cached Credentials 2 (DCC2)", "category": "Windows"},
    3000: {"name": "LM", "category": "Windows"},
    5500: {"name": "NetNTLMv1", "category": "Network"},
    5600: {"name": "NetNTLMv2", "category": "Network"},
    13100: {"name": "Kerberos 5 TGS-REP (etype 23)", "category": "Kerberos"},
    18200: {"name": "Kerberos 5 AS-REP (etype 23)", "category": "Kerberos"},
    1731: {"name": "MSSQL (2012+)", "category": "Database"},
    112: {"name": "Oracle S (11g+)", "category": "Database"},
}
