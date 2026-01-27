"""
LM → NTLM Multi-Step Cracking Workflow

Orchestrates a series of hashcat jobs to maximize password recovery:

Step 1: LM Brute Force
    - Extract 16-char LM halves from pwdump
    - Crack using mode 3000 with brute force (?u?d?s charset)
    - Increment from 1-7 characters

Step 2: Combine LM Results
    - Match cracked halves to users
    - Combine halves into full uppercase plaintexts
    - Handle short passwords (≤7 chars) and confirm ordering

Step 3: NTLM Case Permutation
    - Use combined uppercase plaintexts as wordlist
    - Apply toggle rules to try all case permutations
    - Crack mode 1000 (NTLM) hashes

The workflow automatically chains jobs - when one step completes,
the next step is queued if there are results to process.
"""

import json
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from app import lm_ntlm_tools

logger = logging.getLogger(__name__)


class WorkflowStep(Enum):
    """Steps in the LM → NTLM workflow."""
    LM_BRUTE = "lm_brute"           # Step 1: Crack LM halves
    COMBINE_HALVES = "combine"       # Step 2: Combine results (automatic)
    NTLM_TOGGLE = "ntlm_toggle"      # Step 3: Case permutation on NTLM
    COMPLETED = "completed"          # Workflow finished
    FAILED = "failed"                # Workflow failed


class WorkflowStatus(Enum):
    """Overall workflow status."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class WorkflowState:
    """Tracks the state of an LM → NTLM workflow."""
    workflow_id: str
    agent_id: str
    created_at: str
    status: WorkflowStatus = WorkflowStatus.PENDING
    current_step: WorkflowStep = WorkflowStep.LM_BRUTE

    # Original input
    original_pwdump: str = ""  # Path to original pwdump file

    # LM extraction data
    lm_extraction_file: Optional[str] = None
    total_users_with_lm: int = 0
    total_unique_halves: int = 0

    # Job tracking
    lm_job_id: Optional[str] = None
    lm_job_status: Optional[str] = None
    lm_halves_cracked: int = 0

    ntlm_job_id: Optional[str] = None
    ntlm_job_status: Optional[str] = None
    ntlm_passwords_cracked: int = 0
    unique_ntlm_hashes: int = 0  # Total unique NTLM hashes to crack

    # Results
    users_both_halves_cracked: int = 0
    users_short_password_cracked: int = 0
    final_passwords_recovered: int = 0

    # Error tracking
    error_message: Optional[str] = None

    # Timestamps
    lm_started_at: Optional[str] = None
    lm_completed_at: Optional[str] = None
    ntlm_started_at: Optional[str] = None
    ntlm_completed_at: Optional[str] = None
    workflow_completed_at: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "workflow_id": self.workflow_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "status": self.status.value,
            "current_step": self.current_step.value,
            "original_pwdump": self.original_pwdump,
            "lm_extraction_file": self.lm_extraction_file,
            "total_users_with_lm": self.total_users_with_lm,
            "total_unique_halves": self.total_unique_halves,
            "lm_job_id": self.lm_job_id,
            "lm_job_status": self.lm_job_status,
            "lm_halves_cracked": self.lm_halves_cracked,
            "ntlm_job_id": self.ntlm_job_id,
            "ntlm_job_status": self.ntlm_job_status,
            "ntlm_passwords_cracked": self.ntlm_passwords_cracked,
            "unique_ntlm_hashes": self.unique_ntlm_hashes,
            "users_both_halves_cracked": self.users_both_halves_cracked,
            "users_short_password_cracked": self.users_short_password_cracked,
            "final_passwords_recovered": self.final_passwords_recovered,
            "error_message": self.error_message,
            "lm_started_at": self.lm_started_at,
            "lm_completed_at": self.lm_completed_at,
            "ntlm_started_at": self.ntlm_started_at,
            "ntlm_completed_at": self.ntlm_completed_at,
            "workflow_completed_at": self.workflow_completed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WorkflowState":
        """Deserialize from dictionary."""
        state = cls(
            workflow_id=data["workflow_id"],
            agent_id=data["agent_id"],
            created_at=data["created_at"],
        )
        state.status = WorkflowStatus(data.get("status", "pending"))
        state.current_step = WorkflowStep(data.get("current_step", "lm_brute"))
        state.original_pwdump = data.get("original_pwdump", "")
        state.lm_extraction_file = data.get("lm_extraction_file")
        state.total_users_with_lm = data.get("total_users_with_lm", 0)
        state.total_unique_halves = data.get("total_unique_halves", 0)
        state.lm_job_id = data.get("lm_job_id")
        state.lm_job_status = data.get("lm_job_status")
        state.lm_halves_cracked = data.get("lm_halves_cracked", 0)
        state.ntlm_job_id = data.get("ntlm_job_id")
        state.ntlm_job_status = data.get("ntlm_job_status")
        state.ntlm_passwords_cracked = data.get("ntlm_passwords_cracked", 0)
        state.unique_ntlm_hashes = data.get("unique_ntlm_hashes", 0)
        state.users_both_halves_cracked = data.get("users_both_halves_cracked", 0)
        state.users_short_password_cracked = data.get("users_short_password_cracked", 0)
        state.final_passwords_recovered = data.get("final_passwords_recovered", 0)
        state.error_message = data.get("error_message")
        state.lm_started_at = data.get("lm_started_at")
        state.lm_completed_at = data.get("lm_completed_at")
        state.ntlm_started_at = data.get("ntlm_started_at")
        state.ntlm_completed_at = data.get("ntlm_completed_at")
        state.workflow_completed_at = data.get("workflow_completed_at")
        return state


def get_lm_brute_args() -> list[str]:
    """
    Get hashcat arguments for LM brute force attack.

    Uses charset with uppercase letters, digits, and common special chars.
    Increments from 1 to 7 characters (max per LM half).
    """
    return [
        "-m", "3000",           # LM hash mode
        "-a", "3",              # Brute force attack
        "-1", "?u?d?s",         # Custom charset: uppercase + digits + specials
        "?1?1?1?1?1?1?1",       # 7-char mask
        "-i",                   # Increment mode
        "--increment-min", "1",
        "--increment-max", "7",
        "-O",                   # Optimized kernels
    ]


def get_ntlm_toggle_args(wordlist_path: str, rules_path: str) -> list[str]:
    """
    Get hashcat arguments for NTLM case permutation attack.

    Uses the combined LM plaintexts as a wordlist and applies
    toggle rules to try all case combinations.
    """
    return [
        "-m", "1000",           # NTLM hash mode
        "-a", "0",              # Wordlist attack
        wordlist_path,          # Wordlist with uppercase plaintexts
        "-r", rules_path,       # Toggle rules for case permutation
        "-O",                   # Optimized kernels
    ]


def create_toggle_rules_file(output_path: str, max_length: int = 14) -> str:
    """
    Create a hashcat rules file for case toggling.

    Generates rules to toggle case at each position up to max_length.
    For a password of N characters, this creates 2^N combinations.

    Args:
        output_path: Path to write the rules file
        max_length: Maximum password length to support

    Returns:
        Path to created rules file
    """
    rules = []

    # Base rule (no change - all uppercase from LM)
    rules.append(":")

    # Toggle each position (T0 = toggle position 0, etc.)
    for i in range(max_length):
        rules.append(f"T{i}")

    # Toggle pairs of positions
    for i in range(max_length):
        for j in range(i + 1, max_length):
            rules.append(f"T{i} T{j}")

    # Toggle triplets (most common patterns)
    for i in range(max_length):
        for j in range(i + 1, max_length):
            for k in range(j + 1, min(max_length, j + 4)):  # Limit triplet span
                rules.append(f"T{i} T{j} T{k}")

    # Common patterns: lowercase all, then uppercase first
    rules.append("l")       # All lowercase
    rules.append("l c")     # Lowercase, then capitalize first
    rules.append("l C")     # Lowercase, then uppercase first char

    # Toggle all (full lowercase)
    toggle_all = " ".join(f"T{i}" for i in range(max_length))
    rules.append(toggle_all)

    # Write rules file
    with open(output_path, "w") as f:
        f.write("\n".join(rules))

    logger.info(f"Created toggle rules file with {len(rules)} rules at {output_path}")
    return output_path


def create_comprehensive_toggle_rules(output_path: str, max_length: int = 14) -> str:
    """
    Create a comprehensive toggle rules file that covers all 2^N combinations.

    For passwords up to 14 chars, we need 2^14 = 16,384 rules to cover all
    possible case permutations. Each rule is a combination of toggle operations
    for positions 0-13 (T0 through TD in hashcat).

    Args:
        output_path: Path to write the rules file
        max_length: Maximum password length (capped at 14 for LM-derived passwords)

    Returns:
        Path to created rules file
    """
    # Cap at 14 since LM passwords max out at 14 chars
    max_length = min(max_length, 14)

    rules = [":"]  # Start with identity rule (no toggles = keep uppercase)

    # Generate all 2^max_length combinations using binary counting
    # Each bit position determines whether to toggle that character
    # bit 0 set -> toggle position 0, bit 1 set -> toggle position 1, etc.
    for bits in range(1, 2 ** max_length):
        toggles = []
        for pos in range(max_length):
            if bits & (1 << pos):
                # Hashcat toggle positions: 0-9 are T0-T9, 10-13 are TA-TD
                if pos < 10:
                    toggles.append(f"T{pos}")
                else:
                    toggles.append(f"T{chr(ord('A') + pos - 10)}")
        if toggles:
            rules.append(" ".join(toggles))

    # Write rules file
    with open(output_path, "w") as f:
        f.write("\n".join(rules))

    logger.info(f"Created comprehensive toggle rules with {len(rules)} rules at {output_path}")
    return output_path


class LMtoNTLMWorkflow:
    """
    Manages the LM → NTLM multi-step cracking workflow.
    """

    def __init__(self, data_dir: str):
        """
        Initialize the workflow manager.

        Args:
            data_dir: Base directory for workflow data storage
        """
        self.data_dir = Path(data_dir)
        self.workflows_dir = self.data_dir / "workflows"
        self.workflows_dir.mkdir(parents=True, exist_ok=True)

        # Rules file path
        self.rules_file = self.data_dir / "toggle_case.rule"
        self._ensure_rules_file()

    def _ensure_rules_file(self) -> None:
        """Ensure the toggle rules file exists."""
        if not self.rules_file.exists():
            create_comprehensive_toggle_rules(str(self.rules_file))

    def _get_workflow_dir(self, workflow_id: str) -> Path:
        """Get directory for a specific workflow."""
        return self.workflows_dir / workflow_id

    def _get_state_file(self, workflow_id: str) -> Path:
        """Get path to workflow state file."""
        return self._get_workflow_dir(workflow_id) / "state.json"

    def save_state(self, state: WorkflowState) -> None:
        """Save workflow state to disk."""
        workflow_dir = self._get_workflow_dir(state.workflow_id)
        workflow_dir.mkdir(parents=True, exist_ok=True)

        state_file = self._get_state_file(state.workflow_id)
        with open(state_file, "w") as f:
            json.dump(state.to_dict(), f, indent=2)

    def load_state(self, workflow_id: str) -> Optional[WorkflowState]:
        """Load workflow state from disk."""
        state_file = self._get_state_file(workflow_id)
        if not state_file.exists():
            return None

        with open(state_file, "r") as f:
            return WorkflowState.from_dict(json.load(f))

    def list_workflows(self) -> list[WorkflowState]:
        """List all workflows."""
        workflows = []
        for workflow_dir in self.workflows_dir.iterdir():
            if workflow_dir.is_dir():
                state = self.load_state(workflow_dir.name)
                if state:
                    workflows.append(state)
        return sorted(workflows, key=lambda w: w.created_at, reverse=True)

    def create_workflow(
        self,
        agent_id: str,
        pwdump_content: str,
        workflow_id: Optional[str] = None,
    ) -> tuple[WorkflowState, dict]:
        """
        Create a new LM → NTLM workflow.

        Args:
            agent_id: Target agent ID
            pwdump_content: Raw pwdump file content
            workflow_id: Optional workflow ID (auto-generated if not provided)

        Returns:
            Tuple of (WorkflowState, job_data for first step)
        """
        import time

        if not workflow_id:
            workflow_id = f"lm2nt-{int(time.time())}"

        # Create workflow directory
        workflow_dir = self._get_workflow_dir(workflow_id)
        workflow_dir.mkdir(parents=True, exist_ok=True)

        # Save original pwdump
        pwdump_file = workflow_dir / "original.pwdump"
        with open(pwdump_file, "w") as f:
            f.write(pwdump_content)

        # Extract LM halves
        extraction = lm_ntlm_tools.extract_lm_halves_from_pwdump(pwdump_content)

        if extraction.total_unique_halves == 0:
            raise ValueError("No LM hashes found in pwdump content")

        # Save extraction mapping
        extraction_file = workflow_dir / "lm_extraction.json"
        lm_ntlm_tools.save_extraction_result(extraction, str(extraction_file))

        # Generate LM halves hash file
        halves_file = workflow_dir / "lm_halves.txt"
        halves_content = lm_ntlm_tools.generate_lm_hashfile(extraction)
        with open(halves_file, "w") as f:
            f.write(halves_content)

        # Create workflow state
        state = WorkflowState(
            workflow_id=workflow_id,
            agent_id=agent_id,
            created_at=datetime.now().isoformat(),
            status=WorkflowStatus.RUNNING,
            current_step=WorkflowStep.LM_BRUTE,
            original_pwdump=str(pwdump_file),
            lm_extraction_file=str(extraction_file),
            total_users_with_lm=extraction.total_users_with_lm,
            total_unique_halves=extraction.total_unique_halves,
            lm_job_id=f"{workflow_id}-lm",
            lm_started_at=datetime.now().isoformat(),
        )

        self.save_state(state)

        # Build job data for LM cracking step
        job_data = {
            "job_id": state.lm_job_id,
            "hash_content": halves_content,
            "hash_filename": "lm_halves.txt",
            "hashcat_args": get_lm_brute_args(),
            "priority": 10,  # High priority for workflow jobs
            "metadata": {
                "job_type": "lm",
                "workflow_id": workflow_id,
                "workflow_step": "lm_brute",
            },
        }

        logger.info(
            f"Created workflow {workflow_id}: "
            f"{extraction.total_unique_halves} LM halves from {extraction.total_users_with_lm} users"
        )

        return state, job_data

    def on_lm_job_complete(
        self,
        workflow_id: str,
        potfile_content: str,
        stats: dict,
    ) -> tuple[WorkflowState, Optional[dict]]:
        """
        Handle LM job completion and prepare NTLM job if applicable.

        Args:
            workflow_id: Workflow ID
            potfile_content: Cracked LM halves potfile content
            stats: Job completion stats

        Returns:
            Tuple of (updated WorkflowState, optional job_data for NTLM step)
        """
        state = self.load_state(workflow_id)
        if not state:
            raise ValueError(f"Workflow {workflow_id} not found")

        workflow_dir = self._get_workflow_dir(workflow_id)

        # Update LM job status
        state.lm_job_status = "completed"
        state.lm_completed_at = datetime.now().isoformat()
        state.lm_halves_cracked = stats.get("recovered", 0)

        # Save LM potfile
        lm_potfile = workflow_dir / "lm_cracked.potfile"
        with open(lm_potfile, "w") as f:
            f.write(potfile_content)

        # Load and update extraction with cracked plaintexts
        extraction = lm_ntlm_tools.load_extraction_result(state.lm_extraction_file)
        extraction = lm_ntlm_tools.process_lm_potfile(potfile_content, extraction)

        # Get stats
        lm_stats = lm_ntlm_tools.get_cracking_stats(extraction)
        state.users_both_halves_cracked = lm_stats["users_both_halves_cracked"]
        state.users_short_password_cracked = lm_stats["users_short_password_cracked"]

        # Save updated extraction
        lm_ntlm_tools.save_extraction_result(extraction, state.lm_extraction_file)

        # Check if we have users ready for NTLM attack
        if lm_stats["ready_for_ntlm_attack"] > 0:
            # Generate NTLM attack files
            ntlm_dir = workflow_dir / "ntlm_attack"
            ntlm_files = lm_ntlm_tools.generate_ntlm_attack_files(extraction, str(ntlm_dir))

            # Read the files for job submission
            with open(ntlm_files["hash_file"], "r") as f:
                ntlm_hashes = f.read()
            # IMPORTANT: Read with latin-1 to preserve extended ASCII characters
            with open(ntlm_files["wordlist_file"], "r", encoding="latin-1") as f:
                lm_plaintexts = f.read()

            # Update state for NTLM step
            state.current_step = WorkflowStep.NTLM_TOGGLE
            state.ntlm_job_id = f"{workflow_id}-ntlm"
            state.ntlm_started_at = datetime.now().isoformat()
            state.unique_ntlm_hashes = ntlm_files.get("unique_hashes", 0)

            self.save_state(state)

            # Build NTLM job data
            # We need to send both the hash file and wordlist
            # The agent will need to handle this specially
            job_data = {
                "job_id": state.ntlm_job_id,
                "hash_content": ntlm_hashes,
                "hash_filename": "ntlm_hashes.txt",
                "hashcat_args": [
                    "-m", "1000",
                    "-a", "0",
                    # Wordlist will be added by agent from metadata
                    "-O",
                ],
                "priority": 10,
                "metadata": {
                    "job_type": "ntlm_toggle",
                    "workflow_id": workflow_id,
                    "workflow_step": "ntlm_toggle",
                    "wordlist_content": lm_plaintexts,
                    "wordlist_filename": "lm_plaintexts.txt",
                    "rules_content": self._get_toggle_rules_content(),
                    "rules_filename": "toggle_case.rule",
                },
            }

            logger.info(
                f"Workflow {workflow_id}: LM step complete, "
                f"starting NTLM toggle attack for {lm_stats['ready_for_ntlm_attack']} users"
            )

            return state, job_data
        else:
            # No users ready for NTLM attack - workflow complete
            state.current_step = WorkflowStep.COMPLETED
            state.status = WorkflowStatus.COMPLETED
            state.workflow_completed_at = datetime.now().isoformat()

            self.save_state(state)

            logger.info(
                f"Workflow {workflow_id}: Complete (no users with both LM halves cracked)"
            )

            return state, None

    def on_ntlm_job_complete(
        self,
        workflow_id: str,
        potfile_content: str,
        stats: dict,
    ) -> WorkflowState:
        """
        Handle NTLM job completion and finalize workflow.

        Args:
            workflow_id: Workflow ID
            potfile_content: Cracked NTLM hashes potfile content
            stats: Job completion stats

        Returns:
            Updated WorkflowState
        """
        state = self.load_state(workflow_id)
        if not state:
            raise ValueError(f"Workflow {workflow_id} not found")

        workflow_dir = self._get_workflow_dir(workflow_id)

        # Update NTLM job status
        state.ntlm_job_status = "completed"
        state.ntlm_completed_at = datetime.now().isoformat()
        state.ntlm_passwords_cracked = stats.get("recovered", 0)

        # Calculate final user recovery count
        # If all unique NTLM hashes were cracked, all users with cracked LM halves are recovered
        # (Multiple users can share the same NTLM hash = same password)
        if state.unique_ntlm_hashes > 0 and state.ntlm_passwords_cracked >= state.unique_ntlm_hashes:
            # 100% of unique hashes cracked = 100% of users recovered
            state.final_passwords_recovered = state.users_both_halves_cracked
        else:
            # Partial crack - use the count of unique hashes as a conservative estimate
            state.final_passwords_recovered = state.ntlm_passwords_cracked

        # Save NTLM potfile
        ntlm_potfile = workflow_dir / "ntlm_cracked.potfile"
        with open(ntlm_potfile, "w") as f:
            f.write(potfile_content)

        # Mark workflow complete
        state.current_step = WorkflowStep.COMPLETED
        state.status = WorkflowStatus.COMPLETED
        state.workflow_completed_at = datetime.now().isoformat()

        self.save_state(state)

        logger.info(
            f"Workflow {workflow_id}: Complete! "
            f"Recovered {state.final_passwords_recovered} NTLM passwords"
        )

        return state

    def on_job_error(self, workflow_id: str, error: str) -> WorkflowState:
        """
        Handle job error in workflow.

        Args:
            workflow_id: Workflow ID
            error: Error message

        Returns:
            Updated WorkflowState
        """
        state = self.load_state(workflow_id)
        if not state:
            raise ValueError(f"Workflow {workflow_id} not found")

        state.status = WorkflowStatus.FAILED
        state.current_step = WorkflowStep.FAILED
        state.error_message = error
        state.workflow_completed_at = datetime.now().isoformat()

        self.save_state(state)

        logger.error(f"Workflow {workflow_id}: Failed - {error}")

        return state

    def _get_toggle_rules_content(self) -> str:
        """Get the content of the toggle rules file."""
        self._ensure_rules_file()
        with open(self.rules_file, "r") as f:
            return f.read()

    def get_workflow_summary(self, workflow_id: str) -> dict:
        """
        Get a summary of workflow progress.

        Args:
            workflow_id: Workflow ID

        Returns:
            Dict with workflow summary
        """
        state = self.load_state(workflow_id)
        if not state:
            return {"error": "Workflow not found"}

        return {
            "workflow_id": state.workflow_id,
            "status": state.status.value,
            "current_step": state.current_step.value,
            "progress": {
                "total_users_with_lm": state.total_users_with_lm,
                "total_unique_halves": state.total_unique_halves,
                "lm_halves_cracked": state.lm_halves_cracked,
                "users_both_halves_cracked": state.users_both_halves_cracked,
                "unique_ntlm_hashes": state.unique_ntlm_hashes,
                "ntlm_passwords_cracked": state.ntlm_passwords_cracked,
                "final_passwords_recovered": state.final_passwords_recovered,
            },
            "jobs": {
                "lm_job": {
                    "id": state.lm_job_id,
                    "status": state.lm_job_status,
                    "started": state.lm_started_at,
                    "completed": state.lm_completed_at,
                },
                "ntlm_job": {
                    "id": state.ntlm_job_id,
                    "status": state.ntlm_job_status,
                    "started": state.ntlm_started_at,
                    "completed": state.ntlm_completed_at,
                } if state.ntlm_job_id else None,
            },
            "created_at": state.created_at,
            "completed_at": state.workflow_completed_at,
            "error": state.error_message,
        }
