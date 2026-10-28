#!/usr/bin/env python3
"""SWE-bench Pro specialization of the deterministic TB2 controller."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tb2_persona_pilot.controller import (  # noqa: E402,F401
    ROLE_OVERLAYS as _BASE_ROLE_OVERLAYS,
    Controller as _BaseController,
    TurnRecord,
    distinctive,
)

ROLE_OVERLAYS = dict(_BASE_ROLE_OVERLAYS)
ROLE_OVERLAYS.update({
    "first_time_pr_contributor": {
        "id": "first_pr_scope_and_evidence",
        "behaviour": (
            "a careful first-time contributor: ask for one small concrete step at a time, keep the patch "
            "isolated from unrelated work, and ask for a failure-specific explanation you can repeat in review"
        ),
        "forbidden": (
            "asking the agent to commit, push, open a PR, clean/reset the repository, inventing pre-existing "
            "changes, accepting generic Git tutorials instead of task-specific evidence, or weakening the issue"
        ),
    },
    "maintainer_contract_reviewer": {
        "id": "public_contract_coverage_reviewer",
        "behaviour": (
            "a maintainer reviewing the public contract: trace one explicit clause at a time to the plan, patch, "
            "and focused evidence; ask about visible contradictions and distinguish verified from unverified claims"
        ),
        "forbidden": (
            "inventing acceptance criteria, requiring unrelated cleanup or exhaustive validation, prescribing an "
            "unsupported implementation, or treating absent private knowledge as part of the contract"
        ),
    },
    "boundary_case_test_reviewer": {
        "id": "grounded_boundary_case_reviewer",
        "behaviour": (
            "a boundary-case reviewer: follow repository-visible branches and public examples, examine one grounded "
            "adjacent case at a time, and request existing focused validation or a temporary reproduction"
        ),
        "forbidden": (
            "inventing edge cases without repository or public-contract support, modifying tests, demanding the full "
            "suite, or turning a temporary reproduction into delivered test code"
        ),
    },
    "downstream_compatibility_reviewer": {
        "id": "repository_visible_compatibility_reviewer",
        "behaviour": (
            "a downstream maintainer: trace actual repository callers, formats, states, and error paths affected by "
            "the patch, and request narrow evidence for preserved or intentionally changed behavior"
        ),
        "forbidden": (
            "inventing external customers, deployments, schemas, migration duties, or undocumented consumers; "
            "claiming broad compatibility from one narrow check; or forcing an internal implementation"
        ),
    },
})

PERSONA_COMMUNICATION_STYLES = {
    "manager_no_code": {
        "verbosity": "concise",
        "explanation": "business conclusions and evidence-calibrated status only",
        "ordering": "recommendation -> actual progress -> decisions",
        "length": "at most 3 short points after the delivery-format requirement is disclosed",
    },
}

COMMUNICATION_STYLE = {
    "verbosity": "concise",
    "explanation": "one task-specific step or causal explanation at a time",
    "ordering": "scope isolation -> patch explanation -> final review",
    "length": "at most 6 short sentences, or 12 when disclosing a bound requirement",
}

ONLINE_VERIFICATION_POLICY = "event-and-transcript-v2"


@dataclass
class Controller(_BaseController):
    """Remove TB2's CSV probes while preserving scheduling and policy validation.

    The A/B switch is declared here, not in the reused TB2 controller: `final-only`
    is an experiment of this pilot, so the field that hides mid-episode verification
    belongs to this subclass.
    """

    online_verification_enabled: bool = True

    def online_verification_plan(
        self,
        turn: int,
        *,
        snapshot_changed: bool,
        completion_claimed: bool,
        transcript_changed: bool = False,
    ) -> Dict[str, List[str]]:
        """Select active requirements whose relevant evidence changed.

        Explicit simulator requests remain handled by ``apply_decision``.  The
        automatic path runs only after the first agent response to a newly
        disclosed requirement, after a code snapshot change, or when the agent
        claims completion. Rubric checks also refresh when their transcript changes.
        Final verification is still unconditional at turn
        99 via ``verify_outcome``.
        """
        if not self.online_verification_enabled:
            return {}
        plan: Dict[str, List[str]] = {}
        for entry in self.ledger.active():
            reasons: List[str] = []
            if entry.introduced_turn == turn:
                reasons.append("first_response_after_disclosure")
            if snapshot_changed:
                reasons.append("snapshot_changed")
            if completion_claimed:
                reasons.append("completion_claim")
            if transcript_changed and (getattr(entry, "checker", {}) or {}).get("id") == "rubric_judge":
                reasons.append("transcript_changed")
            if reasons:
                plan[entry.ref] = reasons
        return plan

    @contextlib.contextmanager
    def _only(self, requirement_refs: List[str]):
        """Narrow what the reused TB2 loop sees, without duplicating it.

        TB2's `verify_active` iterates `self.ledger.active()` and owns the
        record_check / infra_failures / typed-event bookkeeping.  The event-driven
        subset is this pilot's concern, so rather than widening the TB2 signature or
        copying that loop, the ledger view is narrowed for the duration of the call.
        """
        requested = set(requirement_refs)
        original = self.ledger.active
        had_own = "active" in vars(self.ledger)
        self.ledger.active = lambda: [entry for entry in original() if entry.ref in requested]
        try:
            yield
        finally:
            if had_own:
                self.ledger.active = original
            else:
                del self.ledger.active

    def verify_active(self, turn: int, transcript=None, requirement_refs: Optional[List[str]] = None):
        """Verify every active requirement, or only the ones an event selected."""
        if requirement_refs is None:
            return super().verify_active(turn, transcript)
        if not requirement_refs:
            return []
        with self._only(requirement_refs):
            return super().verify_active(turn, transcript)

    def _validate_candidate(self, cand, proof):
        problems = super()._validate_candidate(cand, proof)
        if os.environ.get('SWE_PERSONA_CALIBRATION_ENABLED') == '0':
            # Keep structural validation; only the startup control proof is optional.
            missing_proof = f"not_proven_achievable:{cand.checker['id']}"
            problems = [problem for problem in problems if problem != missing_proof]
        return problems

    def _achievability_proof(self, validation_report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if os.environ.get('SWE_PERSONA_CALIBRATION_ENABLED') == '0':
            return {'calibration_status': 'skipped', 'source': '--no-calibration'}
        from rubric_checker import grading_identity
        proof: Dict[str, Any] = {}
        sources: List[str] = []
        if validation_report:
            arm = (validation_report.get("arms") or {}).get("reference_compliant", {})
            for checker_id, result in (arm.get("checks") or {}).items():
                proof[checker_id] = result.get("status")
            sources.append("validate_bindings.py::reference_compliant")
        validation_dir = Path(__file__).resolve().parent / "runs" / "validation"
        gate_dir = os.environ.get('PCB_RUBRIC_GATE_DIR')
        if gate_dir:
            validation_dir = Path(gate_dir)
            marker = json.loads((validation_dir/'gate.json').read_text(encoding='utf-8'))
            if (marker.get('profile') != 'swe-bench-pro-shell' or marker.get('passed') is not True
                    or marker.get('worker_exit_code') != 0):
                raise ValueError('A passed SWE-bench Pro shell calibration gate is required')
        for path in sorted(validation_dir.glob("rubric_report*.json")):
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if report.get("gate_passed") and report.get("grading_identity") == grading_identity():
                proof["rubric_judge"] = "pass"
                sources.append(path.name)
                break
        proof["source"] = " + ".join(sources)
        return proof

    def run_probes(self, turn: int):
        return []

    def end_blockers(self, turn: int) -> List[str]:
        blockers: List[str] = []
        if self.due_item(turn):
            blockers.append("a requirement disclosure is due this turn")
        for candidate in self.selected:
            entry = self.ledger.entries.get(f"{candidate.requirement_id}@1")
            if entry is not None and entry.activation_status == "validated_undisclosed" and candidate.schedule["required"]:
                blockers.append(f"required requirement {entry.ref} not disclosed yet")
        if self.online_verification_enabled:
            for entry in self.ledger.active():
                if entry.satisfaction_status != "met":
                    blockers.append(f"{entry.ref} is {entry.satisfaction_status}, not met")
        if self.current_digest == self.initial_digest:
            blockers.append("the repository has no task patch yet")
        return blockers

    def build_observation(self, *args, **kwargs):
        obs = super().build_observation(*args, **kwargs)
        if not self.online_verification_enabled:
            obs["allowed_actions"] = [
                action for action in obs["allowed_actions"] if action != "request_verification"
            ]
            obs["registered_checkers"] = []
            for entry in obs.get("ledger", []):
                entry.pop("checker", None)
            obs["verification_mode"] = "final_only"
        else:
            obs["verification_mode"] = "online"
        return obs

    def validate_decision(self, decision, observation):
        errors = super().validate_decision(decision, observation)
        if not self.online_verification_enabled and decision.get("verification_requests"):
            errors.append(
                "final-only mode forbids rubric/evidence subcheck requests before final review"
            )
            return errors
        for request in decision.get("verification_requests") or []:
            entry = self.ledger.entries.get(request.get("requirement_ref"))
            if entry is None:
                continue  # The base validator reports unknown requirements.
            bound = entry.checker
            if (request.get("checker_id"), request.get("version")) != (
                bound["id"], bound["version"]
            ):
                errors.append("verification must use the requirement's bound checker and version")
            try:
                overrides = json.loads(request.get("parameters") or "{}")
            except (ValueError, TypeError):
                continue  # The base validator reports malformed parameters.
            if isinstance(overrides, dict) and any(
                key not in bound.get("parameters", {}) or bound["parameters"][key] != value
                for key, value in overrides.items()
            ):
                errors.append("verification parameters must not override the frozen binding")
        return errors
