#!/usr/bin/env python3
"""Run one persona-interactive episode on a pinned SWE-bench Pro instance."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import shlex
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import dockerx
from agent import TerminalAgent, HARNESS_PROTOCOL_VERSION
from checkers import CheckerRegistry
from controller import (
    COMMUNICATION_STYLE,
    ONLINE_VERIFICATION_POLICY,
    PERSONA_COMMUNICATION_STYLES,
    ROLE_OVERLAYS,
    Controller,
)
from dockerx import Container, Mount
from disclosure import NativeDisclosureTracker, native_requirement_inventory, audit_delivery
from judge import FINAL_ONLY, ONLINE, run_judge
from ledger import Ledger
from llm import CallLog, Llm, SchemaRepairFailed
from registry import applicable_candidates, build_candidates, load_persona
from rubric_checker import grading_identity
from simulator import UserSimulator, render_system_prompt, SIMULATOR_PROTOCOL_VERSION
from task_adapter import NATIVE_TEST_POLICY, TaskManifest, build_environment_overlay, decode_public_field
from verifier import compute_metrics, verify_outcome

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"


def agent_terminal_reason(status: str, turn: int, max_turns: int, disclosure_complete: bool,
                          controller_allows_completion: bool = True) -> Optional[str]:
    """Normal completion needs current acceptance evidence; budgets always stop."""
    # The mini bridge enforces a fresh model-step budget per user turn. Using
    # that budget ends the current turn, not the interactive episode.
    if status == "budget_exhausted" and turn >= max_turns:
        return "turn_budget_exhausted"
    if status == "done" and disclosure_complete and controller_allows_completion:
        return "agent_submitted"
    if turn >= max_turns:
        return "turn_budget_exhausted"
    return None

VAGUE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["vague_request", "kept", "omitted"],
    "properties": {
        "vague_request": {"type": "string"},
        "kept": {"type": "array", "items": {"type": "string"}},
        "omitted": {"type": "array", "items": {"type": "string"}},
    },
}

UNSAFE_PUBLIC_CONTRACT_RE = re.compile(
    r"\b(?:the\s+)?gold(?:en)?[_ -]?patch\b|\btest[_ -]?patch\b|\boracle[_ -]?patch\b"
    r"|\breference[_ -]?(?:patch|answer|implementation)\b|\brequired[_ -]?test[_ -]?names?\b",
    re.IGNORECASE,
)


def safe_complete_public_contract(manifest: TaskManifest) -> str:
    """Render the native public task while rejecting benchmark-answer provenance."""
    # `interface` is intentionally excluded: this dataset field may have been
    # derived from a reference patch. The native issue and requirements are the
    # only provenance-safe inputs to the coding agent.
    fields = [decode_public_field(manifest.row[key]).strip()
              for key in ("problem_statement", "requirements")]
    text = "\n\n".join(field for field in fields if field)
    match = UNSAFE_PUBLIC_CONTRACT_RE.search(text)
    if match:
        raise RuntimeError(
            f"unsafe public contract provenance marker: {match.group(0)!r}; task is not eligible for multiturn"
        )
    # Fenced code blocks are not inline anchors; matching across their backticks
    # otherwise consumes intervening prose and hides later genuine anchors.
    inline_anchor = r"(?<!`)`([^`\n]+)`(?!`)"
    problem_anchors = {item.strip().lower() for item in re.findall(inline_anchor, fields[0])}
    requirement_anchors = {item.strip().lower() for item in re.findall(inline_anchor, fields[1])}
    if problem_anchors and requirement_anchors and not problem_anchors & requirement_anchors:
        raise RuntimeError(
            "incoherent public contract: problem statement and requirements have disjoint explicit anchors"
        )
    return text
VAGUE_SYSTEM = """Below is the complete prompt a native SWE-bench Pro run hands the coding agent: the full specification plus its constraints, including that the tests are already written and must not be modified.

Write as this specific user persona; do not borrow the identity, experience, constraints, or goals of another persona.
Persona name: {persona_name}
Technical context: {technical_context}
Primary goal: {primary_goal}
Interaction preferences: {interaction_preferences}
Constraints: {constraints}

You are the person who filed this task. You hold all of it in your head, but you are not going to say it all at once. Write only the first short message you send a coding agent.
Keep the visible symptom, why it is confusing, and the desired direction. Omit repository paths, symbol names, exact output strings, error-code lists, platform-specific hint wording, tests, commits, and anything that reads like a complete specification. The harness tells the agent the environment facts and the test policy on its own, so do not restate those either; everything else you withhold now is yours to reveal later as the agent asks. First person, no bullets, no code, at most 65 words. Also list what you kept and omitted."""
# FIRST_PR_PREFIX = (
#     "This is my first contribution here. Please work only in the local checkout and do not clean/reset it, "
#     "commit, push, or open a PR for me. "
# )


def make_first_message(llm: Llm, manifest: TaskManifest,
                       persona: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    persona = persona or load_persona("first_time_pr_contributor")
    attributes = persona.get("attributes") or {}
    system = VAGUE_SYSTEM.format(
        persona_name=persona.get("name") or persona.get("id") or "task reporter",
        technical_context=attributes.get("technical_context") or "Use only the public task context.",
        primary_goal=attributes.get("primary_goal") or "Resolve the public task.",
        interaction_preferences=attributes.get("interaction_preferences") or "Be concise and task-grounded.",
        constraints=attributes.get("constraints") or "Do not add requirements beyond the public task.",
    )
    rejections: List[str] = []
    for _attempt in range(4):
        prompt = "## Native SWE-bench Pro agent prompt\n" + manifest.native_agent_prompt()
        if rejections:
            prompt += "\n\nRemove these leaked details and rewrite: " + ", ".join(rejections)
        result = llm.json_obj(
            [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            VAGUE_SCHEMA, schema_name="vague_request", role="adapter.first_message", max_output_tokens=1200,
        )
        message = result["vague_request"].strip()
        # The opening request is intentionally vague.  Reject obvious exact
        # implementation identifiers even when they are public, while the
        # manifest's hidden-marker audit separately protects oracle material.
        public_hashes = re.findall(r"\b[0-9a-f]{12,40}\b", message.lower())
        exact_paths = [
            item.strip().rstrip(".,;:")
            for item in re.findall(r"(?:^|\s)(?:/?[\w.-]+/)+[\w.-]+", message)
            # Reads like a path to the regex but is ordinary prose, not a
            # repository path.  Kept as a carve-out so a persona that happens to
            # write it is not sent into a pointless rewrite loop.
            if item.strip().rstrip(".,;:") != "clean/reset"
        ]
        leaks = public_hashes + exact_paths
        if not leaks:
            manifest.assert_no_leak(message, "first user message")
            result["vague_request"] = message
            result["leak_check"] = "clean"
            return result
        rejections = leaks
    raise RuntimeError(f"could not generate a vague first message; leaked {rejections}")


def assert_rubric_gate(model: str, interactive: bool) -> None:
    if not interactive or os.environ.get('SWE_PERSONA_CALIBRATION_ENABLED') == '0':
        return
    from rubric_checker import GROUNDING_PROTOCOL, grading_identity
    gate_dir = Path(os.environ.get("PCB_RUBRIC_GATE_DIR", HERE / "runs" / "validation"))
    path = gate_dir / f"rubric_report.{model}.{GROUNDING_PROTOCOL}.json"
    if not path.is_file():
        raise SystemExit(f"missing rubric gate for {model}: run `python3 validate_rubric.py --judge-model {model}`")
    report = json.loads(path.read_text(encoding="utf-8"))
    if not report.get("gate_passed"):
        raise SystemExit(f"rubric gate did not pass for {model}: {report.get('failures')}")
    if report.get("grading_identity") != grading_identity():
        raise SystemExit("stale rubric gate: current scoring protocol/sources require new calibration")
    if report.get("judge_model") != model or report.get("samples") != 3:
        raise SystemExit("rubric gate model or sample count mismatch")


def stop_on_evaluator_error(controller, results):
    """Do not turn evaluator faults into another coding-agent revision."""
    if not any(result.evidence.get("error_category") for result in results):
        return False
    controller.invalid_reasons.append("requirement_evaluator_error")
    controller.end_state = "evaluation_invalid"
    return True


def environment_card(manifest: TaskManifest, overlay: Dict[str, Any]) -> str:
    lines = [
        f"- repository: {manifest.row['repo']} at {manifest.base_commit}",
        f"- working directory: {overlay['working_directory']}",
        f"- runtime: {overlay['runtime']}",
        f"- limits: {overlay['cpus']} cpu, {overlay['memory']}, network {overlay['network']}",
        "- permissions: " + "; ".join(overlay["permissions"]),
        "- registered test runner: /harness/run_script.sh",
    ]
    return "\n".join(lines)


def agent_task_brief(manifest: TaskManifest, overlay: Dict[str, Any]) -> str:
    """What the coding agent reads in its system prompt, below the environment facts.

    The problem statement and requirements are the provenance-safe public
    contract. In the progressive arm they may reach the agent only through user
    messages, so this prompt contains environment facts and test policy only.
    """
    sections = [
        environment_card(manifest, overlay),
        "## Test policy\n" + NATIVE_TEST_POLICY,
    ]
    return "\n\n".join(sections)


def simulator_task_binding(
    manifest: TaskManifest, selected: Sequence[Any], turn_budget: int,
    native_tracker: Optional[NativeDisclosureTracker] = None,
) -> Dict[str, Any]:
    """Layer 3 of the persona simulator prompt.

    The simulator plays the person who filed this task, so it holds the provenance-safe
    specification -- and under progressive disclosure it is the *only* party that does.  The
    agent knows its container and the test policy and nothing else about the goal, so what
    reaches it depends on what this persona chooses to say, turn by turn.
    """
    native_tracker = native_tracker or NativeDisclosureTracker(
        native_requirement_inventory(manifest.row["requirements"])
    )
    return {
        "task_id": manifest.task_id,
        "source": f"{manifest.dataset}@{manifest.dataset_version}",
        "applicable_families": ["reviewable-source-patch", "public-error-scenario", "validation-entrypoint"],
        "frozen_contract": {
            "problem_statement": decode_public_field(manifest.row["problem_statement"]),
            "requirements": decode_public_field(manifest.row["requirements"]),
        },
        "bound_requirement_refs": [f"{candidate.requirement_id}@1" for candidate in selected],
        "native_requirement_inventory": [
            {"id": item.id, "wording": item.wording, "wording_sha256": item.wording_sha256}
            for item in native_tracker.inventory
        ],
        "native_requirement_disclosure_rule": (
            "Every listed native requirement is mandatory. When the controller marks the native "
            "bundle due, include every still-missing wording exactly in the agent-visible user_message."
        ),
        "turn_budget": turn_budget,
        "task_specification": safe_complete_public_contract(manifest),
        "task_specification_use": (
            "This is what you are ultimately asking for. The coding agent has NOT been given the "
            "problem statement or requirements: it knows its container and that it must not touch "
            "the tests, so everything else it learns "
            "about the goal is something you told it. Release it gradually, in your own words as "
            "this persona and at the level of detail your disclosure policy allows. Native requirements "
            "are the exception: when due, use their validated wording exactly. Do not volunteer an evolved "
            "requirement whose trigger has not fired. "
            "Use it to tell whether what the agent reports covers what you need, and to answer "
            "what it asks."
        ),
    }


def _contains_clause(message: str, clause: str) -> bool:
    return re.sub(r"\s+", " ", clause).strip() in re.sub(r"\s+", " ", message).strip()


def original_contract_errors(message: str, manifest: TaskManifest) -> List[str]:
    errors = []
    for name in ("problem_statement", "interface"):
        clause = decode_public_field(manifest.row[name]).strip()
        if clause and not _contains_clause(message, clause):
            errors.append(f"original {name} must appear with its validated wording in this agent-visible message")
    return errors


def safe_progressive_contract_errors(message: str, manifest: TaskManifest) -> List[str]:
    """Validate the provenance-safe contract used by progressive episodes."""
    errors = []
    problem = decode_public_field(manifest.row["problem_statement"]).strip()
    if problem and not _contains_clause(message, problem):
        errors.append("original problem_statement must appear with validated wording")
    match = UNSAFE_PUBLIC_CONTRACT_RE.search(message)
    if match:
        errors.append(f"unsafe public contract provenance marker: {match.group(0)!r}")
    return errors


def native_fallback_decision(
    observation: Dict[str, Any], tracker: NativeDisclosureTracker, manifest: TaskManifest,
) -> Dict[str, Any]:
    """Construct the fail-closed simulator fallback after bounded LLM retries."""
    due = observation.get("requirement_to_disclose")
    prefix = ""
    disclosures: List[Dict[str, Any]] = []
    action = "answer"
    if due:
        action = "disclose"
        prefix = "I also need this additional condition: " + str(due["statement"])
        missing_markers = [
            str(marker) for marker in due.get("must_include_verbatim") or []
            if str(marker) not in prefix
        ]
        if missing_markers:
            prefix += "\n" + "\n".join(missing_markers)
        disclosures = [{
            "requirement_ref": due["requirement_ref"],
            "operation": due["operation"],
            "replaces": list(due.get("replaces") or []),
        }]
    public_problem = decode_public_field(manifest.row["problem_statement"]).strip()
    contract_prefix = "\n\n".join(part for part in (
        prefix,
        "Here is the complete original request:\n" + public_problem,
    ) if part.strip())
    message = tracker.fallback_message(contract_prefix)
    return {
        "turn_id": observation["turn"],
        "observation_id": observation["observation_id"],
        "action": action,
        "user_message": message,
        "ledger_updates": [],
        "disclosures": disclosures,
        "verification_requests": [],
        "evidence_refs": [],
        "branch_log": [],
        "end_state": None,
        "rationale": "Prevalidated native-requirement fallback after bounded simulator retries.",
    }


def safe_simulator_fallback_decision(observation: Dict[str, Any]) -> Dict[str, Any]:
    """Continue safely when ordinary simulator decisions fail policy validation."""
    due = observation.get("requirement_to_disclose")
    disclosures: List[Dict[str, Any]] = []
    if due:
        action = "disclose"
        message = "I also need this additional condition: " + str(due["statement"])
        for marker in due.get("must_include_verbatim") or []:
            if str(marker) not in message:
                message += "\n" + str(marker)
        disclosures = [{
            "requirement_ref": due["requirement_ref"],
            "operation": due["operation"],
            "replaces": list(due.get("replaces") or []),
        }]
    else:
        action = "feedback"
        message = (
            "Recommendation: continue the implementation and independent verification.\n"
            "Progress: I am treating the reported status as a claim until registered checks support it.\n"
            "Decision: no decision is needed from me right now."
        )
    return {
        "turn_id": observation["turn"],
        "observation_id": observation["observation_id"],
        "action": action,
        "user_message": message,
        "ledger_updates": [],
        "disclosures": disclosures,
        "verification_requests": [],
        "evidence_refs": [],
        "branch_log": [],
        "end_state": None,
        "rationale": "Prevalidated safe fallback after bounded simulator retries.",
        "disclosure_source": "simulator_fallback",
    }


INTERNAL_SIMULATOR_LANGUAGE_RE = re.compile(
    r"\bchk[-_ ]?\d+\b|\bevidence[_ ]ref\b|\brubric (?:judge|verdict)\b"
    r"|\bchecker id\b|\bledger[_ ]updates?\b|\bartifact eligibility\b",
    re.IGNORECASE,
)


def simulator_user_message_errors(message: str) -> List[str]:
    match = INTERNAL_SIMULATOR_LANGUAGE_RE.search(str(message or ""))
    return ([f"user_message exposes evaluator internals: {match.group(0)!r}"] if match else [])


def contradictory_followup_errors(message: str, observation: Dict[str, Any]) -> List[str]:
    recent = observation.get("recent_dialogue") or []
    prior_user = "\n".join(str(item.get("text") or "") for item in recent
                           if item.get("role") == "user").lower()
    prior_agent = "\n".join(str(item.get("text") or "") for item in recent
                            if item.get("role") == "agent").lower()
    accepted_no_actions = re.search(
        r"\b(?:without|no) (?:any )?(?:further )?(?:repository )?actions?\b",
        prior_user,
    )
    acknowledged_unavailable = (
        re.search(r"\b(?:unavailable|cannot|can't|blocked)\b", prior_agent)
        and re.search(r"\b(?:unavailable|unverified|blocker|no further)\b", prior_user)
    )
    demands_execution = re.search(
        # Match affirmative requests rather than status mentions or negations.
        # "checks not run" must not trigger another simulator retry/fallback.
        r"(?:^|[.!?;,]\s+|\b(?:please|can you|could you|would you|"
        r"you (?:must|should|need to)|(?:need|want|require) you to)\s+)"
        r"(?:run|execute|re-run|rerun|check the actual|perform)\b",
        str(message or ""), re.IGNORECASE,
    )
    if (accepted_no_actions or acknowledged_unavailable) and demands_execution:
        return ["user_message re-demands an action already accepted as unavailable"]
    return []


def select_simulator_message(simulator, controller, observation, tracker, manifest):
    """Validate every proposal and fallback before it can reach the agent."""
    native_due = observation.get("native_requirements_due_this_turn", False)

    def errors_for(decision):
        errors = controller.validate_decision(decision, observation)
        errors += simulator_user_message_errors(decision.get("user_message", ""))
        errors += contradictory_followup_errors(decision.get("user_message", ""), observation)
        if native_due:
            if decision.get("action") == "end":
                errors.append("cannot end before the agent receives the due original contract")
            errors = [error for error in errors
                      if not error.startswith("user_message must be at most")
                      and not error.startswith("communication_style allows at most")]
            errors += tracker.validation_errors(decision["user_message"])
            errors += safe_progressive_contract_errors(decision["user_message"], manifest)
        return errors

    rejections = []
    for _attempt in range(4):
        try:
            decision = simulator.decide(observation, rejections[-1] if rejections else None)
        except SchemaRepairFailed as exc:
            rejections.append([f"decision was not schema-valid: {exc.errors}"])
            continue
        errors = errors_for(decision)
        if not errors:
            return decision, rejections, []
        rejections.append(errors)
    # Mandatory content must not depend on any proposal having valid structure.
    decision = (native_fallback_decision(observation, tracker, manifest)
                if native_due else safe_simulator_fallback_decision(observation))
    decision["disclosure_source"] = "simulator_fallback"
    errors = errors_for(decision)
    return (None if errors else decision), rejections, errors


def hidden_test_names(manifest: TaskManifest, public_go_tests: Sequence[str] = ()) -> List[str]:
    """Test identifiers that exist only in the hidden test patch.

    Some fail-to-pass identifiers name existing public tests. Only exact Go test
    declarations verified in the immutable base commit are exempted here.
    Hidden-only identifiers and subtest suffixes remain isolated.
    """
    try:
        names = ast.literal_eval(str(manifest.row["fail_to_pass"]))
    except (KeyError, ValueError, SyntaxError):
        return []
    if not isinstance(names, (list, tuple, set)):
        return []
    public = set(public_go_tests)
    return [str(name) for name in names if len(str(name)) >= 8 and str(name) not in public]


def public_base_go_tests(container: Container, base_commit: str) -> List[str]:
    """Read committed test declarations before agent edits; fail closed on errors."""
    rc, stdout, _stderr = container.sh(
        "git grep -h -E '^func Test[A-Za-z0-9_]+\\(t \\*testing\\.T\\)' "
        + shlex.quote(base_commit) + " -- '*_test.go'", timeout=60)
    if rc != 0:
        return []
    return sorted(set(re.findall(r'^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)', stdout, re.M)))


def build_agent_harness(destination: Path, official_runner: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    runner = destination / "run_script.sh"
    shutil.copy2(official_runner, runner)
    runner.chmod(runner.stat().st_mode | 0o111)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", default="progressive_persona",
                        choices=["original", "progressive_persona"])
    parser.add_argument("--persona", default="first_time_pr_contributor")
    parser.add_argument(
        "--data-version", default="legacy",
        help="versioned binding set under bindings/ (legacy preserves the original hard-coded pilot)",
    )
    parser.add_argument("--max-turns", type=int, default=6)
    parser.add_argument("--max-steps", type=int, default=12,
                        help="maximum shell steps per user turn in the restored shell/reply harness")
    parser.add_argument("--max-evolved", type=int, default=2)
    parser.add_argument("--run-id", default=None)
    parser.add_argument(
        "--runs-root", type=Path, default=None,
        help="root directory for this episode; defaults to swebenchpro_persona_pilot/runs",
    )
    parser.add_argument("--agent-model", default="gpt-5.6-luna")
    parser.add_argument("--simulator-model", default=None)
    parser.add_argument("--judge-model", default=None)
    parser.add_argument("--rubric-model", default=None)
    task = parser.add_mutually_exclusive_group(required=True)
    task.add_argument("--instance-id")
    task.add_argument("--dataset-index", type=int)
    parser.add_argument("--index-base", type=int, choices=[0, 1], default=0)
    parser.add_argument("--image-ref", default=None, help="prepared local image; defaults to the dataset image")
    parser.add_argument(
        "--prepared-image", action="store_true",
        help="assert that --image-ref is already clean and future-history-pruned",
    )
    parser.add_argument(
        "--first-message-file", type=Path, default=None,
        help="reuse a frozen adapter JSON/text file (the batch runner gives both arms the same file)",
    )
    parser.add_argument(
        "--rubric-feedback", choices=["online", "final-only"], default="online",
        help="online exposes per-turn rubric evidence; final-only runs the same rubric only at final review",
    )
    parser.add_argument(
        "--disable-rubric-checker",
        action="store_true",
        help=(
            "skip rubric_judge (including its evidence/subchecks) for a non-scoring timing trial; "
            "evolved-requirement verdicts are recorded as unknown"
        ),
    )
    parser.add_argument("--adapter-model", default=None)
    parser.add_argument("--keep-container", action="store_true")
    args = parser.parse_args()
    if args.max_steps < 1 or args.max_turns < 1:
        parser.error("turn and shell-step budgets must be positive")
    if args.arm == "progressive_persona" and args.max_turns < 3:
        parser.error("progressive disclosure requires at least three available user turns")

    models = {
        "agent": args.agent_model,
        "simulator": args.simulator_model or args.agent_model,
        "judge": args.judge_model or args.agent_model,
        "adapter": args.adapter_model or args.agent_model,
    }
    models["rubric_judge"] = args.rubric_model or models["judge"]
    if args.disable_rubric_checker and args.rubric_feedback != "online":
        raise SystemExit("--disable-rubric-checker is a legacy timing mode and cannot be combined with final-only")
    if not args.disable_rubric_checker:
        assert_rubric_gate(models["rubric_judge"], args.arm == "progressive_persona")

    run_id = args.run_id or f"{args.arm}-{time.strftime('%Y%m%dT%H%M%S')}"
    runs_root = (args.runs_root or (HERE / "runs")).resolve()
    run_dir = runs_root / run_id
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise SystemExit(
            f"run id {run_id!r} already exists at {run_dir}; choose a new --run-id to avoid "
            "overwriting or colliding with an active episode"
        ) from exc
    call_log = CallLog(path=run_dir / "llm_calls.jsonl")
    clients: Dict[str, Llm] = {}

    def llm_for(name: str) -> Llm:
        if name not in clients:
            clients[name] = Llm(model=name, call_log=call_log)
        return clients[name]

    agent_llm = llm_for(models["agent"])
    simulator_llm = llm_for(models["simulator"])
    judge_llm = llm_for(models["judge"])
    adapter_llm = llm_for(models["adapter"])
    rubric_llm = None if args.disable_rubric_checker else llm_for(models["rubric_judge"])
    print("models: " + json.dumps(models), flush=True)
    if args.disable_rubric_checker:
        print("rubric checker: disabled for timing trial; this run is not rubric-scored", flush=True)

    manifest = TaskManifest.from_dataset(
        instance_id=args.instance_id,
        dataset_index=args.dataset_index,
        index_base=args.index_base,
    )
    image_ref = args.image_ref or manifest.docker_image
    if args.prepared_image and not args.image_ref:
        raise SystemExit("--prepared-image requires --image-ref")
    manifest.environment = build_environment_overlay(manifest, image_ref)
    assets = manifest.materialize_checker_assets(run_dir / ".checker_assets", FIXTURES)
    agent_harness = build_agent_harness(run_dir / "agent_harness", assets / "run_script.sh")
    checkers = CheckerRegistry(
        assets,
        run_dir,
        base_commit=manifest.base_commit,
        judge_llm=rubric_llm,
        rubric_checker_enabled=not args.disable_rubric_checker,
    )
    ledger = Ledger()
    native_tracker = NativeDisclosureTracker(native_requirement_inventory(manifest.row["requirements"]))
    max_evolved = args.max_evolved if args.arm == "progressive_persona" else 0
    candidates = build_candidates(
        manifest, args.persona, max_evolved=max_evolved, data_version=args.data_version
    )
    selected = applicable_candidates(candidates, max_evolved)
    if args.arm == 'progressive_persona' and max_evolved > 0 and not selected:
        raise ValueError('Progressive persona evaluation loaded no persona requirements')
    required_candidates = [c for c in candidates if c.applicable and c.schedule.get('required', True)]
    if args.arm == 'progressive_persona' and any(c not in selected for c in required_candidates):
        raise ValueError('The evolved requirement budget omits a required persona requirement')
    expected_trigger_by_template = {
        "first_pr_isolated_patch": "approach_visible",
        "first_pr_patch_explanation": "first_patch",
        "maintainer_clause_coverage": "approach_visible",
        "maintainer_contract_matrix": "completion_claim",
        "boundary_grounded_counterexample": "approach_visible",
        "boundary_adjacent_invariant": "first_patch",
        "student_patch_and_boundary_reasoning": "first_patch",
        "compat_existing_consumer": "approach_visible",
        "compat_focused_handoff": "completion_claim",
    }
    invalid_guards = [candidate.requirement_id for candidate in selected
                      if (candidate.schedule.get("trigger_guard") != "applicability_prevalidated"
                          or expected_trigger_by_template.get(candidate.template_id)
                          != candidate.schedule.get("trigger_event"))]
    if invalid_guards:
        raise RuntimeError("unvalidated evolved requirement guards: " + ", ".join(invalid_guards))
    rubric_config_payload = [
        {
            "requirement_id": candidate.requirement_id,
            "template_id": candidate.template_id,
            "checker": candidate.checker,
            "schedule": candidate.schedule,
        }
        for candidate in selected
    ]
    rubric_config_hash = hashlib.sha256(
        json.dumps(rubric_config_payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    run_slug = re.sub(r"[^a-z0-9_.-]+", "-", run_id.lower()).strip("-.")
    # Docker names are global per daemon and batches reuse a task's run id, so hash the run directory.
    run_hash = hashlib.sha256(str(run_dir).encode()).hexdigest()[:10]
    controller = Controller(
        manifest=manifest,
        ledger=ledger,
        checkers=checkers,
        candidates=candidates,
        selected=selected,
        run_dir=run_dir,
        max_turns=args.max_turns,
        entrypoint_path="/app",
        snapshot_tag_prefix=f"swepro-snap-{run_slug[:45]}-{run_hash}",
        online_verification_enabled=(args.rubric_feedback == "online"),
    )
    validation_path = HERE / "runs" / "validation" / "validation_report.json"
    validation = json.loads(validation_path.read_text()) if validation_path.is_file() else None
    controller.register_candidates(validation)

    container_mounts = [Mount(str(agent_harness), "/harness", read_only=True)]
    cache_root = Path(os.environ.get("PCB_SUBMODULE_CACHE", Path.home() / ".cache/personacodebench/submodules"))
    if manifest.row["repo"] == "future-architect/vuls":
        container_mounts.append(Mount(str(cache_root / "vuls-integration.git"),
                                      "/opt/pcb-submodule-cache/vuls-integration.git", read_only=True))
    elif manifest.row["repo"] == "gravitational/teleport":
        container_mounts.append(Mount(str(cache_root / "teleport-webassets.git"),
                                      "/opt/pcb-submodule-cache/teleport-webassets.git", read_only=True))
    container = Container(
        name=f"swepro-{run_slug[:35]}-{run_hash}",
        image=image_ref,
        mounts=container_mounts,
        memory=manifest.limits["memory"], cpus=str(manifest.limits["cpus"]), network="none",
        base_commit=manifest.base_commit,
    )
    transcript: List[Dict[str, Any]] = []
    turn_records: List[Dict[str, Any]] = []
    started = time.time()
    error: Optional[str] = None
    judge_output = None
    outcome: Dict[str, Any] = {}
    metrics: Dict[str, Any] = {"arm": args.arm, "error": "episode_not_started"}
    started_container = False
    history_guard: Dict[str, Any] = {}
    agent: Optional[TerminalAgent] = None
    # A persona requirement is required only after its semantic trigger actually
    # caused an agent-visible disclosure. Untriggered patch-review or handoff
    # templates are not silently forced by the turn deadline.
    required_evolved: set[str] = {f'{c.requirement_id}@1' for c in selected if c.schedule.get('required', True)}
    disclosed_evolved: set[str] = set()
    delivery_audit = {"valid": None, "errors": [], "messages": []}
    public_go_tests: List[str] = []

    complete_contract_message_ids = []
    agent_turns_used = 0
    artifacts_ready = False
    finalization_started = False
    finalization_complete = False
    api_interrupted = False
    from swe_persona.time_limit import InteractionExpired, arm_interaction, disarm_interaction
    api_recovery_assessment = None
    turn = 1

    def finalize():
        nonlocal outcome, metrics, judge_output, delivery_audit
        nonlocal complete_contract_message_ids, agent_turns_used, disclosed_evolved
        nonlocal artifacts_ready, finalization_started, finalization_complete
        finalization_started = True
        from swe_persona.time_limit import begin_verification
        begin_verification()
        agent_turns_used = turn
        final_image, final_digest, _changed = controller.snapshot(container, 99)
        artifacts_ready = True
        disclosed_evolved = {ref for item in transcript if item.get("role") == "user"
                             for ref in item.get("disclosure_refs", []) if not ref.startswith("native.req.")}
        outcome = verify_outcome(
            ledger, checkers, final_image, final_digest, turn=99,
            reference_checkers=None, transcript=transcript,
        )
        if args.arm == "progressive_persona":
            judge_output = run_judge(
                judge_llm,
                [{key: value for key, value in item.items()
                  if key in ("role", "message_id", "turn", "status", "text", "evidence_refs")}
                 for item in transcript],
                ledger.events,
                [dict(result.public_summary(), turn=result.turn) for result in checkers.results],
                verification_mode=ONLINE if args.rubric_feedback == "online" else FINAL_ONLY,
                episode_budget={
                    "max_agent_turns": controller.max_turns,
                    "agent_turns_used": agent_turns_used,
                    "max_agent_steps_per_turn": args.max_steps,
                    "requirement_deadlines": {
                        candidate.requirement_id: candidate.schedule["deadline_turn"]
                        for candidate in selected
                    },
                },
                requirement_refs=[f"{candidate.requirement_id}@1" for candidate in selected],
                persona_id=args.persona,
                # `assert_no_leak` only guards rendered observations; the simulator's own reply is
                # never re-checked, so the judge's deterministic audit is the last chance to catch a
                # leak into a message the agent actually read.
                hidden_markers=list(manifest.hidden_markers()) + hidden_test_names(manifest, public_go_tests),
            )
        complete_contract_message_ids = [
            str(item["message_id"])
            for item in transcript
            if item.get("role") == "user"
            and not (original_contract_errors(str(item.get("text") or ""), manifest)
                     if args.arm == "original"
                     else safe_progressive_contract_errors(str(item.get("text") or ""), manifest))
        ]
        if args.arm == "original" and not complete_contract_message_ids:
            # The original arm carries the byte-for-byte upstream rendering; quoted
            # dataset fields need not also match their decoded representation.
            complete_contract_message_ids = ["u-1"]
        if args.arm == "progressive_persona":
            delivery_audit = audit_delivery(
                transcript, call_log.calls, native_tracker, required_evolved, controller.max_turns,
                mini_receipts=(getattr(agent, "delivery_receipts", []) if agent else []),
                mini_trajectory_path=(run_dir / "minisweagent" / "trajectory.json"),
            )
        if args.arm == "progressive_persona" and (
            native_tracker.missing_ids() or not complete_contract_message_ids
            or not required_evolved <= disclosed_evolved
            or not delivery_audit["valid"]
        ):
            controller.invalid_reasons.append("required_disclosure_incomplete")
        metrics = compute_metrics(
            args.arm, outcome, ledger, controller, transcript, judge_output,
            max_turns=controller.max_turns, agent_turns_used=agent_turns_used,
        )
        finalization_complete = True

    try:
        container.start()
        started_container = True
        if args.prepared_image:
            history_guard = container.verify_prepared_base(manifest.base_commit, manifest.source_commit)
        else:
            history_guard = container.prepare_clean_base(manifest.base_commit, manifest.source_commit)
        _image, _digest, _changed = controller.snapshot(container, 0)
        if container.file_list():
            raise RuntimeError("selected SWE-bench Pro image did not start from a clean git status")
        public_go_tests = public_base_go_tests(container, manifest.base_commit)

        from swe_persona.time_limit import begin_interaction
        # The unified row cap is enforced by the host interaction watchdog.
        interaction_deadline=begin_interaction(float(os.environ.get('SWE_PERSONA_INTERACTION_SECONDS','86400')))
        arm_interaction(interaction_deadline)

        persona = load_persona(args.persona)
        task_binding = simulator_task_binding(manifest, selected, controller.max_turns, native_tracker)
        simulator = UserSimulator(
            simulator_llm,
            render_system_prompt(
                persona,
                ROLE_OVERLAYS[args.persona],
                task_binding,
                manifest.environment,
                PERSONA_COMMUNICATION_STYLES.get(args.persona, COMMUNICATION_STYLE),
            ),
        )
        os.environ["PCB_RUN_DIR"] = str(run_dir)
        agent = TerminalAgent(
            agent_llm, container, agent_task_brief(manifest, manifest.environment),
            max_steps_per_turn=args.max_steps,
            workdir="/app", command_timeout=600.0,
        )

        if args.arm == "original":
            first = {"vague_request": manifest.native_problem_statement,
                     "kept": ["complete public contract"], "omitted": [],
                     "leak_check": "not applicable: original arm exposes the public contract"}
        elif args.first_message_file:
            raw_first = args.first_message_file.read_text(encoding="utf-8")
            try:
                loaded = json.loads(raw_first)
            except json.JSONDecodeError:
                loaded = {"vague_request": raw_first.strip(), "kept": [], "omitted": [], "leak_check": "external"}
            if not isinstance(loaded, dict) or not str(loaded.get("vague_request") or "").strip():
                raise RuntimeError(f"invalid first-message file: {args.first_message_file}")
            first = loaded
            manifest.assert_no_leak(first["vague_request"], "frozen first user message")
        elif args.arm == "progressive_persona" and os.environ.get("PCB_COMPLETE_NATIVE_OPENING") == "1":
            complete = safe_complete_public_contract(manifest)
            first = {"vague_request": complete, "kept": ["complete safe public contract"],
                     "omitted": [], "leak_check": "fail-closed provenance scan"}
        else:
            first = make_first_message(adapter_llm, manifest, persona)
        (run_dir / "first_message.json").write_text(json.dumps(first, ensure_ascii=False, indent=2), encoding="utf-8")
        user_message = first["vague_request"]
        user_message_source = "original_public_contract" if args.arm == "original" else "simulator_opening"
        pending_evolved_refs: List[str] = []
        turn = 1
        while True:
            message_id = f"u-{turn}"
            native_refs = native_tracker.record_agent_visible_message(
                message_id=message_id,
                turn=turn,
                text=user_message,
                source=user_message_source,
            )
            disclosure_refs = native_refs + pending_evolved_refs
            transcript.append({"role": "user", "message_id": message_id, "turn": turn,
                               "text": user_message, "evidence_refs": [],
                               "disclosure_refs": disclosure_refs, "visible_to_agent": True,
                               "disclosures": [
                                   {"requirement_id": ref,
                                    "type": "original" if ref in native_refs else "evolved"}
                                   for ref in disclosure_refs
                               ]})
            pending_evolved_refs = []
            agent_turn = agent.run_turn(user_message, turn)
            transcript.append({"role": "agent", "message_id": agent_turn.message_id, "turn": turn,
                               "status": agent_turn.status, "text": agent_turn.reply,
                               "turn_end_reason": agent_turn.turn_end_reason,
                               "shell_steps": len(agent_turn.steps)})
            current_turn_record: Dict[str, Any] = {
                "turn": turn,
                "user_message": dict(transcript[-2]),
                "agent_turn": agent_turn.to_json(),
                "observation": None,
                "decision": None,
                "rejections": [],
                "extra_checks": [],
            }
            turn_records.append(current_turn_record)
            (run_dir / "turns.json").write_text(
                json.dumps(turn_records, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"[turn {turn}] agent status={agent_turn.status} steps={len(agent_turn.steps)}", flush=True)

            image, digest, changed = controller.snapshot(container, turn)
            checkers.record_agent_turn(turn, agent_turn.steps, digest)
            files = container.file_list()
            has_patch = digest != controller.initial_digest
            if has_patch and "first_patch" not in controller.fired:
                controller.add_event("first_patch", turn, {"snapshot": digest})
            if not has_patch and agent_turn.reply.strip() and "first_plan" not in controller.fired:
                controller.add_event("first_plan", turn, {"reply_id": agent_turn.message_id})
            if (has_patch or agent_turn.reply.strip()) and "approach_visible" not in controller.fired:
                controller.add_event("approach_visible", turn, {"via": "patch" if has_patch else "message"})
            new_completion_claim = (
                agent_turn.status == "done" and "completion_claim" not in controller.fired
            )
            if new_completion_claim:
                controller.add_event("completion_claim", turn, {"reply_id": agent_turn.message_id})
            controller.last_transcript = transcript
            probes = controller.run_probes(turn)
            verification_plan = (
                controller.online_verification_plan(
                    turn,
                    snapshot_changed=changed,
                    completion_claimed=new_completion_claim,
                    transcript_changed=True,
                )
                if args.rubric_feedback == "online"
                else {}
            )
            for requirement_ref, reasons in verification_plan.items():
                controller.add_event(
                    "verification_triggered",
                    turn,
                    {"requirement": requirement_ref, "reasons": reasons},
                )
            checks = controller.verify_active(
                turn,
                transcript,
                requirement_refs=list(verification_plan),
            ) if verification_plan else []

            if stop_on_evaluator_error(controller, checks):
                # Still run the isolated final review, but never ask the agent
                # to repair an evaluator malfunction.
                break

            disclosed_evolved = {
                ref for item in transcript if item.get("role") == "user"
                for ref in item.get("disclosure_refs", []) if not ref.startswith("native.req.")
            }
            required_evolved.update(disclosed_evolved)
            disclosures_complete = args.arm == "original" or (
                not native_tracker.missing_ids()
                and required_evolved <= disclosed_evolved
                and any(not safe_progressive_contract_errors(item["text"], manifest)
                        for item in transcript if item.get("role") == "user")
            )
            terminal_reason = agent_terminal_reason(
                agent_turn.status, turn, controller.max_turns, disclosures_complete,
                controller_allows_completion=(args.arm == "original" or not controller.end_blockers(turn + 1)),
            )
            if terminal_reason == "agent_submitted":
                controller.end_state = "completed_pending_final"
            if terminal_reason or controller.end_state:
                break

            if args.arm == "original":
                # No persona or new acceptance criteria in the baseline. A request
                # for clarification must not silently terminate its action budget.
                user_message = "The complete acceptance criteria are in my original request. Please proceed using that contract and state any unresolved ambiguity in your final report."
                user_message_source = "original_clarification"
                current_turn_record["next_user_turn"] = turn + 1
                turn += 1
                continue

            agent_view = {"id": agent_turn.message_id, "status": agent_turn.status,
                          "text": agent_turn.reply, "shell_steps_used": len(agent_turn.steps)}
            observation = controller.build_observation(turn + 1, agent_view, files, changed, probes, checks)
            observation["recent_dialogue"] = [
                {"role": item.get("role"), "text": item.get("text", "")}
                for item in transcript[-6:]
                if item.get("role") in {"user", "agent"}
            ]
            native_due = bool(native_tracker.missing_ids()) or not any(
                not safe_progressive_contract_errors(item["text"], manifest)
                for item in transcript if item.get("role") == "user"
            )
            observation["native_requirements_due_this_turn"] = native_due
            observation["native_requirement_status"] = native_tracker.summary()
            if native_due:
                observation["native_requirements_to_disclose"] = [
                    {"id": item.id, "wording": item.wording, "wording_sha256": item.wording_sha256}
                    for item in native_tracker.inventory if item.id in native_tracker.missing_ids()
                ]
                observation["original_contract_due_this_turn"] = {
                    "problem_statement": decode_public_field(manifest.row["problem_statement"]),
                    "rule": "Include the provenance-safe problem statement and due native requirements with validated wording.",
                }
            decision, rejections, fallback_errors = select_simulator_message(
                simulator, controller, observation, native_tracker, manifest
            )
            if decision is None:
                current_turn_record.update({
                    "observation": observation, "rejections": rejections,
                    "fallback_errors": fallback_errors,
                })
                controller.invalid_reasons.append(
                    f"simulator_fallback_invalid:{fallback_errors[0][:120]}"
                )
                break
            extra = controller.apply_decision(decision, observation, turn + 1)
            if stop_on_evaluator_error(controller, extra):
                current_turn_record.update({"observation": observation, "decision": decision,
                    "rejections": rejections, "extra_checks": [item.public_summary() for item in extra]})
                break
            pending_evolved_refs = [
                str(item["requirement_ref"]) for item in decision.get("disclosures") or []
            ]
            if pending_evolved_refs:
                decision["disclosure_message_id"] = f"u-{turn + 1}"
                decision["visible_to_agent"] = True
                for requirement_ref in pending_evolved_refs:
                    ledger.events.append({
                        "requirement": requirement_ref,
                        "kind": "agent_visible_disclosure",
                        "type": "evolved",
                        "turn": turn + 1,
                        "message_id": f"u-{turn + 1}",
                        "visible_to_agent": True,
                    })
            current_turn_record.update({
                "next_user_turn": turn + 1,
                "observation": observation,
                "decision": decision,
                "rejections": rejections,
                "extra_checks": [item.public_summary() for item in extra],
            })
            (run_dir / "turns.json").write_text(json.dumps(turn_records, ensure_ascii=False, indent=2), encoding="utf-8")
            if decision["action"] == "end":
                transcript.append({"role": "user", "message_id": f"u-{turn + 1}", "turn": turn + 1,
                                   "text": decision["user_message"],
                                   "evidence_refs": decision.get("evidence_refs", []), "closing": True})
                controller.end_state = decision.get("end_state")
                break
            user_message = decision["user_message"]
            user_message_source = str(decision.get("disclosure_source") or "simulator")
            turn += 1

        finalize()
    except (Exception, InteractionExpired) as exc:
        from swe_persona.api_recovery import is_api_interruption
        api_interrupted = is_api_interruption(exc)
        error = traceback.format_exc()
        print(error, flush=True)
        if (api_interrupted or isinstance(exc,InteractionExpired)) and started_container and not finalization_started:
            try:
                finalize()
            except Exception:
                error += '\nFinal verification failed:\n' + traceback.format_exc()
    finally:
        disarm_interaction()
        if started_container and not args.keep_container:
            container.remove()

    ledger_payload = ledger.to_json()
    ledger_payload["native_requirements"] = native_tracker.to_json()
    ledger_payload["delivery_audit"] = delivery_audit
    (run_dir / "ledger.json").write_text(
        json.dumps(ledger_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (run_dir / "turns.json").write_text(json.dumps(turn_records, indent=2), encoding="utf-8")
    disclosure_summary = native_tracker.summary()
    missing_evolved = sorted(required_evolved - disclosed_evolved)
    episode_valid = bool(
        error is None
        and (metrics.get("valid_evaluation_coverage") or {}).get("episode_valid", False)
        and not (
            args.arm == "progressive_persona"
            and (disclosure_summary["missing_count"] or not complete_contract_message_ids or missing_evolved
                 or delivery_audit["valid"] is False)
        )
    )
    from swe_persona.api_recovery import transport_was_exhausted
    api_interrupted = api_interrupted or transport_was_exhausted(run_dir.parent/'api')
    if api_interrupted:
        from swe_persona.api_recovery import assess_interrupted
        base_status = (outcome.get('base_task') or {}).get('status')
        native = base_status == 'pass' if base_status in ('pass', 'fail') else None
        states = [item.get('status') for item in outcome.get('evolved_requirements', [])]
        persona = False if 'not_met' in states else True if states and all(v == 'met' for v in states) else None
        if not finalization_complete and persona is True:
            persona = None
        progress = any(item.get('role') == 'agent' and (item.get('text','').strip() or item.get('shell_steps',0))
                       for item in transcript) or bool(agent and getattr(agent, 'broker', None) and agent.broker.commands)
        api_recovery_assessment = assess_interrupted(native, persona, artifacts_available=artifacts_ready,progress=progress,
            integrity=not (judge_output or {}).get('episode_invalid_reasons'))
        episode_valid = api_recovery_assessment['status'] in ('pass', 'fail')
        metrics['base_task_success'] = native
        metrics['joint_success'] = int(api_recovery_assessment['status'] == 'pass') if episode_valid else None
    episode = {
        "api_recovery_assessment": api_recovery_assessment,
        "run_id": run_id,
        "arm": args.arm,
        "persona": args.persona,
        "task": manifest.public_view(),
        "frozen_digest": manifest.frozen_digest(),
        "seconds": round(time.time() - started, 1),
        "models": models,
        "simulator_protocol": SIMULATOR_PROTOCOL_VERSION,
        "agent_harness": {
            "name": os.environ.get("PCB_AGENT_ADAPTER", "portable_shell:ShellAgent"),
            "agent_class": os.environ.get("PCB_AGENT_ADAPTER", "portable_shell:ShellAgent"),
            "protocol_version": HARNESS_PROTOCOL_VERSION,
            "max_rejected_actions_per_turn": 4 if os.environ.get("PCB_AGENT_ADAPTER") == "mini" else None,
            "action_protocol": "shell-or-reply-to-user",
            "max_steps_per_turn": args.max_steps,
            "initialized": agent is not None,
        },
        "arm_contract": {
            "name": args.arm,
            "prompt_surface": (
                "complete_public_contract_on_first_user_turn"
                if args.arm == "original" or os.environ.get("PCB_COMPLETE_NATIVE_OPENING") == "1"
                else "vague_opening_then_simulator_disclosure"
            ),
            "same_agent_shell_steps_per_turn": args.max_steps,
        },
        "native_requirement_disclosure": native_tracker.to_json(),
        "evolved_requirement_disclosure": {
            "required_count": len(required_evolved),
            "disclosed_count": len(required_evolved & disclosed_evolved),
            "missing_count": len(missing_evolved),
            "required_ids": sorted(required_evolved),
            "disclosed_ids": sorted(required_evolved & disclosed_evolved),
            "missing_ids": missing_evolved,
        },
        "original_contract_disclosure": {
            "complete": bool(complete_contract_message_ids),
            "message_ids": complete_contract_message_ids,
            "visible_to_agent": bool(complete_contract_message_ids),
        },
        "episode_valid": episode_valid,
        "base_pass": (int(outcome['base_task']['status']=='pass')
                      if (outcome.get('base_task') or {}).get('status') in ('pass','fail') else None),
        "persona_pass": (
            metrics.get("evolved_requirement_success", {}).get('pass')
            if args.arm == "progressive_persona" else None
        ),
        "joint_success": metrics.get("joint_success") if episode_valid else None,
        "delivery_audit": delivery_audit,
        "terminal_reason": locals().get("terminal_reason"),
        "evaluation_invalid_reason": (
            "required_disclosure_incomplete"
            if args.arm == "progressive_persona" and (
                disclosure_summary["missing_count"] or not complete_contract_message_ids or missing_evolved
                or delivery_audit["valid"] is False
            ) else next(iter((metrics.get("valid_evaluation_coverage") or {}).get("invalid_reasons", [])), None)
        ),
        "rubric_checker_enabled": not args.disable_rubric_checker,
        "rubric_feedback": args.rubric_feedback,
        "online_verification_policy": ONLINE_VERIFICATION_POLICY,
        "rubric_config_hash": rubric_config_hash,
        "rubric_config": rubric_config_payload,
        "grading_identity": grading_identity(),
        "completion_policy": "controller-acceptance-or-budget-v2",
        "first_message_sha256": (
            hashlib.sha256((run_dir / "first_message.json").read_bytes()).hexdigest()
            if (run_dir / "first_message.json").is_file() else None
        ),
        "native_prompt_sha256": manifest.native_prompt_digest(),
        "agent_task_brief_sha256": hashlib.sha256(
            agent_task_brief(manifest, manifest.environment).encode()
        ).hexdigest(),
        "image_ref": image_ref,
        "history_guard": history_guard,
        "self_play": len(set(models.values())) == 1,
        "llm": call_log.totals(),
        "transcript": transcript,
        "events": controller.events,
        "outcome": outcome,
        "metrics": metrics,
        "judge": judge_output,
        "error": error,
    }
    if api_recovery_assessment:
        episode.update(base_pass=api_recovery_assessment['native_pass'],persona_pass=api_recovery_assessment['persona_pass'],
                       terminal_reason='api_interrupted',evaluation_invalid_reason=None if episode_valid else api_recovery_assessment['reason'])
    (run_dir / "episode.json").write_text(json.dumps(episode, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(run_dir / "transcript.md", episode)
    for tag in {f"{controller.snapshot_tag_prefix}-t{value}:latest"
                for value in list(range(0, controller.max_turns + 2)) + [99]}:
        dockerx.remove_image(tag)
    print(f"\n=== {run_id} ===")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"artifacts: {run_dir}")
    return 1 if error else 0


def _load_check_results(path: Path) -> List[Dict[str, Any]]:
    """Load the append-only checker log next to an episode report.

    The JSONL file remains the canonical, full-fidelity artifact.  Markdown uses
    a bounded rendering of those records so reports stay readable and do not
    reproduce hidden test output or large evidence bundles.
    """
    check_path = path.with_name("checks.jsonl")
    if not check_path.is_file():
        return []
    results: List[Dict[str, Any]] = []
    for raw in check_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            results.append(value)
    return results


def _load_turn_records(path: Path) -> List[Dict[str, Any]]:
    turn_path = path.with_name("turns.json")
    if not turn_path.is_file():
        return []
    try:
        value = json.loads(turn_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _markdown_cell(value: Any) -> str:
    text = str(value if value is not None else "—")
    return text.replace("|", "\\|").replace("\n", "<br>")


# --- transcript rendering -------------------------------------------------- #
# The Markdown report inlines the exact prompt and output of every LLM call at the
# point in the conversation where it happened, inside collapsed <details> blocks, so
# a reader can audit what each role actually saw without leaving the transcript.
# `llm_calls.jsonl` stays the canonical full-fidelity record; these renderings are
# bounded so one episode does not produce an unopenable file.
MAX_MESSAGE_CHARS = 8000
MAX_OUTPUT_CHARS = 8000
MAX_STEP_OUTPUT_CHARS = 2000


EXIT_PREFIX_RE = re.compile(r"^\[exit -?\d+\]\n")


class _Bodies:
    """Render each distinct body once; later occurrences point at the first.

    The same text legitimately appears in several places: a shell result is both a
    `shell steps` entry and the user message that fed it back to the agent, and the k
    samples of a rubric check share one prompt.  Rendering it once and pointing at it
    keeps the report complete without repeating megabytes.  A leading `[exit N]` line is
    stripped before hashing, because that is the only difference between the two
    renderings of a shell result.
    """

    def __init__(self) -> None:
        self._first: Dict[str, str] = {}

    @staticmethod
    def _key(content: str) -> str:
        return hashlib.sha256(EXIT_PREFIX_RE.sub("", content).strip().encode("utf-8")).hexdigest()

    def render(self, label: str, content: Any, limit: int, language: str = "") -> List[str]:
        content = "" if content is None else str(content)
        if not content.strip():
            return _fence("", language)
        key = self._key(content)
        first = self._first.get(key)
        if first is not None and first != label:
            return [f"_identical to {first} ({len(content)} characters)_"]
        self._first.setdefault(key, label)
        return _fence(_clip(content, limit), language)

    def note(self, label: str, content: Any) -> None:
        """Register a body rendered outside a fence (a transcript message)."""
        content = "" if content is None else str(content)
        if content.strip():
            self._first.setdefault(self._key(content), label)


def _load_llm_calls(path: Path) -> List[Dict[str, Any]]:
    call_path = path.with_name("llm_calls.jsonl")
    if not call_path.is_file():
        return []
    calls: List[Dict[str, Any]] = []
    for raw in call_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            calls.append(value)
    return calls


def _clip(text: Any, limit: int) -> str:
    text = "" if text is None else str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... {len(text) - limit} characters omitted; see llm_calls.jsonl ...]"


def _fence(text: str, language: str = "") -> List[str]:
    """Fence `text` with enough backticks that its own fences cannot break out."""
    longest = 0
    run = 0
    for char in text:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    ticks = "`" * max(3, longest + 1)
    return [f"{ticks}{language}", text if text else "(empty)", ticks]


def _details(summary: str, body: List[str], open_by_default: bool = False) -> List[str]:
    return (
        [f"<details{' open' if open_by_default else ''}>", f"<summary>{summary}</summary>", ""]
        + body
        + ["", "</details>", ""]
    )


def _shared_prefix(previous: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> int:
    """How many leading messages `current` carries over unchanged from `previous`."""
    count = 0
    for before, after in zip(previous, current):
        if before.get("role") != after.get("role") or before.get("content") != after.get("content"):
            break
        count += 1
    return count


def _call_body(calls: List[Dict[str, Any]], bodies: "_Bodies", context: str = "") -> List[str]:
    """Render each call, showing every message exactly once.

    A coding-agent turn re-sends its whole growing history on every step, so rendering
    each call's full message list would repeat the transcript once per step and make the
    report quadratic in the number of steps.  Only the messages a call adds are rendered;
    the carried-over prefix is summarised, so the full prompt is still reconstructable in
    order without duplication.
    """
    body: List[str] = []
    previous: List[Dict[str, Any]] = []
    for index, call in enumerate(calls, start=1):
        messages = list(call.get("messages") or [])
        header = (
            f"**call {index}/{len(calls)}** — role `{call.get('role')}`, model "
            f"`{call.get('model')}`, attempt {call.get('attempt')}, "
            f"{call.get('input_tokens')} in / {call.get('output_tokens')} out, "
            f"{call.get('latency_sec')}s"
        )
        body += [header, ""]
        carried = _shared_prefix(previous, messages)
        if carried:
            characters = sum(len(str(item.get("content") or "")) for item in messages[:carried])
            body += [
                f"_prompt continues from call {index - 1}: first {carried} message(s) "
                f"unchanged ({characters} characters)_",
                "",
            ]
        for position, message in enumerate(messages[carried:], start=carried + 1):
            role = str(message.get("role", "?"))
            label = f"{context}call {index} · {role} message {position}".strip()
            body += [f"*{role}:*"]
            body += bodies.render(label, message.get("content"), MAX_MESSAGE_CHARS) + [""]
        body += ["*output:*"]
        body += bodies.render(
            f"{context}call {index} · output".strip(), call.get("output_text"), MAX_OUTPUT_CHARS
        ) + [""]
        previous = messages
    return body


def _grounding_label(item: Dict[str, Any]) -> str:
    """`subcheck` grounding already carries its kind in the ref; do not repeat it."""
    kind = str(item.get("kind") or "?")
    ref = str(item.get("ref") or "?")
    return ref if ref.startswith(f"{kind}:") else f"{kind}:{ref}"


def _clause_table(evidence: Dict[str, Any]) -> List[str]:
    clauses = evidence.get("clauses") or {}
    if not clauses:
        return ["No per-clause verdicts were recorded.", ""]
    lines = [
        "| clause | group | verdict | agreement | grounding | reason |",
        "|---|---|---|---:|---|---|",
    ]
    for clause_id, clause in clauses.items():
        grounding = ", ".join(_grounding_label(item) for item in (clause.get("grounding") or [])[:3])
        reason = (clause.get("reasons") or [clause.get("reason") or ""])[0]
        lines.append(
            f"| `{clause_id}` | {_markdown_cell(clause.get('group'))} | "
            f"**{_markdown_cell(clause.get('verdict'))}** | "
            f"{_markdown_cell(clause.get('agreement'))} | {_markdown_cell(grounding or '—')} | "
            f"{_markdown_cell(_clip(reason, 400))} |"
        )
    lines.append("")
    for clause_id, clause in clauses.items():
        text = clause.get("clause")
        if text:
            lines += [f"- `{clause_id}`: {text}"]
    return lines + [""]


def _assign_rubric_calls(
    checks: List[Dict[str, Any]], calls: List[Dict[str, Any]]
) -> Dict[int, List[Dict[str, Any]]]:
    """Map each rubric execution to the judge calls it actually made.

    The call `role` carries the requirement and sample index but not the turn, so a
    requirement checked more than once cannot be split on the role alone.  Calls are
    therefore consumed in log order per requirement, bounded by each execution's
    `ran_at`, which also absorbs the extra calls a schema repair produces.
    """
    pending: Dict[str, List[Dict[str, Any]]] = {}
    for call in calls:
        role = str(call.get("role") or "")
        if not role.startswith("rubric.") or "messages" not in call:
            continue
        requirement = role[len("rubric.") :].rsplit(".sample", 1)[0]
        pending.setdefault(requirement, []).append(call)
    assigned: Dict[int, List[Dict[str, Any]]] = {}
    for index, check in enumerate(checks):
        evidence = check.get("evidence") or {}
        parameters = check.get("parameters") or {}
        requirement = str(evidence.get("requirement") or parameters.get("requirement") or "")
        queue = pending.get(requirement) or []
        ran_at = str(check.get("ran_at") or "")
        taken: List[Dict[str, Any]] = []
        while queue and (not ran_at or str(queue[0].get("ts") or "") <= ran_at):
            taken.append(queue.pop(0))
        assigned[index] = taken
    return assigned


def _rubric_block(check: Dict[str, Any], calls: List[Dict[str, Any]], bodies: "_Bodies") -> List[str]:
    evidence = check.get("evidence") or {}
    parameters = check.get("parameters") or {}
    requirement = evidence.get("requirement") or parameters.get("requirement") or "unknown"
    status = str(check.get("status") or "unknown")
    badge = {"pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN"}.get(status, status.upper())
    turn = check.get("turn")
    phase = "final review" if turn == 99 else f"turn {turn}"
    subcheck = evidence.get("subcheck") or {}
    lines = [
        f"#### rubric check — `{requirement}` — **{badge}** ({phase})", "",
        f"- checker: `{check.get('checker_id')}@{check.get('version')}`, evidence "
        f"`{check.get('evidence_ref')}`, reason `{check.get('reason_code')}`",
        f"- samples: {evidence.get('samples')}, mean agreement "
        f"{evidence.get('judge_agreement_mean')}, judge `{evidence.get('judge_model')}`",
    ]
    if subcheck:
        lines.append(
            f"- deterministic subcheck: `{subcheck.get('checker')}` → **{subcheck.get('status')}** "
            f"(`{subcheck.get('reason_code')}`)"
        )
    if evidence.get("invalid_grounding_refs"):
        lines.append(
            f"- rejected grounding references: {len(evidence['invalid_grounding_refs'])} "
            "(fabricated or outside the snapshot)"
        )
    lines.append("")
    lines += _details(f"rubric verdicts for <code>{requirement}</code>", _clause_table(evidence))
    if calls:
        lines += _details(
            f"rubric judge prompt and raw verdicts — {len(calls)} sample call(s)",
            _call_body(calls, bodies, f"{requirement} · "),
        )
    else:
        lines += ["_No judge call was recorded for this check in `llm_calls.jsonl`._", ""]
    return lines


def _step_body(steps: List[Dict[str, Any]], bodies: "_Bodies", context: str = "") -> List[str]:
    body: List[str] = []
    for step in steps:
        body += [
            f"**step {step.get('index')}** — exit {step.get('exit_code')}"
            + (f" — {step.get('thought')}" if step.get("thought") else ""),
            "",
            "*command:*",
        ]
        index = step.get("index")
        body += bodies.render(
            f"{context}step {index} · command".strip(), step.get("command"),
            MAX_MESSAGE_CHARS, "sh",
        ) + ["", "*output:*"]
        body += bodies.render(
            f"{context}step {index} · output".strip(), step.get("stdout"), MAX_STEP_OUTPUT_CHARS
        ) + [""]
    return body or ["No shell steps were recorded for this turn.", ""]


def write_markdown(
    path: Path,
    episode: Dict[str, Any],
    checker_results: Optional[List[Dict[str, Any]]] = None,
    turn_records: Optional[List[Dict[str, Any]]] = None,
) -> None:
    metrics = episode.get("metrics") or {}
    lines = [
        f"# {episode['run_id']} ({episode['arm']})", "",
        f"- task: `{episode['task']['task_id']}`", f"- persona: `{episode['persona']}`",
        f"- base task: **{'PASS' if metrics.get('base_task_success') else 'FAIL'}**",
        f"- joint success: **{metrics.get('joint_success')}**",
        f"- models: {json.dumps(episode.get('models', {}))}",
        f"- LLM calls: {episode['llm'].get('calls')}", f"- wall time: {episode['seconds']}s", "",
        "## Transcript", "",
    ]
    if checker_results is None:
        checker_results = _load_check_results(path)
    if turn_records is None:
        turn_records = _load_turn_records(path)
    calls = _load_llm_calls(path)
    bodies = _Bodies()
    lines += [
        "Every LLM call is inlined where it happened, collapsed by default: the persona "
        "simulator's prompt and decision, the coding agent's prompts, shell steps and replies, "
        "and each rubric check's judge prompt and per-clause verdicts. `llm_calls.jsonl` and "
        "`checks.jsonl` remain the canonical records; long bodies are clipped here.", "",
    ]
    steps_by_turn = {
        int((record.get("agent_turn") or {}).get("turn")): (record.get("agent_turn") or {}).get("steps") or []
        for record in turn_records
        if (record.get("agent_turn") or {}).get("turn") is not None
    }
    rubric_checks = [item for item in checker_results if item.get("checker_id") == "rubric_judge"]
    rubric_calls = _assign_rubric_calls(rubric_checks, calls)
    rubric_index = {id(check): index for index, check in enumerate(rubric_checks)}
    rubric_by_turn: Dict[Any, List[Dict[str, Any]]] = {}
    for check in rubric_checks:
        rubric_by_turn.setdefault(check.get("turn"), []).append(check)

    rendered_checks: set = set()

    def _calls_for(prefix: str) -> List[Dict[str, Any]]:
        return [call for call in calls if str(call.get("role") or "").startswith(prefix)]

    for item in episode.get("transcript", []):
        turn = item.get("turn")
        if item["role"] == "user":
            lines += [f"### {item['message_id']} — USER (persona `{episode.get('persona')}`)", ""]
            bodies.note(f"the {item['message_id']} message above", item["text"])
            lines += [item["text"].strip(), ""]
            if item.get("evidence_refs"):
                lines += [f"- cited evidence: {', '.join(item['evidence_refs'])}", ""]
            simulator_calls = _calls_for(f"simulator.turn{turn}")
            if simulator_calls:
                lines += _details(
                    f"persona simulator prompt and decision — {len(simulator_calls)} call(s)",
                    _call_body(simulator_calls, bodies, f"{item['message_id']} · "),
                )
            elif turn == 1:
                lines += _details(
                    "first message adaptation prompt",
                    _call_body(_calls_for("adapter.first_message"), bodies, "u-1 · "),
                ) if _calls_for("adapter.first_message") else [
                    "_Opening message was supplied from a frozen file; no adapter call in this episode._",
                    "",
                ]
            continue

        lines += [f"### {item['message_id']} — CODING AGENT ({item.get('status', '')})", ""]
        bodies.note(f"the {item['message_id']} reply above", item["text"])
        lines += [item["text"].strip(), ""]
        # Steps come first so the prompt trail can point at a shell result rather than
        # repeating it: the same bytes are fed back to the agent as a user message.
        steps = steps_by_turn.get(turn) or []
        if steps:
            lines += _details(
                f"shell steps — {len(steps)} step(s)",
                _step_body(steps, bodies, f"{item['message_id']} · "),
            )
        agent_calls = _calls_for(f"agent.turn{turn}")
        if agent_calls:
            lines += _details(
                f"coding agent prompts and outputs — {len(agent_calls)} call(s)",
                _call_body(agent_calls, bodies, f"{item['message_id']} · "),
            )
        for check in rubric_by_turn.get(turn) or []:
            rendered_checks.add(id(check))
            lines += _rubric_block(check, rubric_calls.get(rubric_index[id(check)], []), bodies)

    final_checks = rubric_by_turn.get(99) or []
    if final_checks:
        lines += ["## Final review", ""]
        for check in final_checks:
            rendered_checks.add(id(check))
            lines += _rubric_block(check, rubric_calls.get(rubric_index[id(check)], []), bodies)
    # A check whose turn has no agent message in the transcript (a truncated or errored
    # episode) must still appear: dropping it would hide a recorded verdict.
    orphans = [check for check in rubric_checks if id(check) not in rendered_checks]
    if orphans:
        lines += [
            "## Rubric checks with no matching transcript turn", "",
            "These executions are recorded in `checks.jsonl` but their turn has no agent "
            "message in this transcript.", "",
        ]
        for check in orphans:
            lines += _rubric_block(check, rubric_calls.get(rubric_index[id(check)], []), bodies)
    judge_calls = _calls_for("judge")
    if judge_calls:
        lines += ["## Interaction judge", ""]
        judge = episode.get("judge") or {}
        lines += [
            f"- total {judge.get('total')}/{judge.get('max_total')} over "
            f"{len(judge.get('scored_items') or [])} scored item(s), mode "
            f"`{judge.get('verification_mode')}`", "",
        ]
        lines += _details(
            f"interaction judge prompt and verdicts — {len(judge_calls)} call(s)",
            _call_body(judge_calls, bodies, "judge · "),
        )
    lines += ["## Evolved requirements", ""]
    for requirement in (episode.get("outcome") or {}).get("evolved_requirements", []):
        lines += [
            f"### {requirement['requirement']} — {requirement['status']}",
            f"- checker: `{requirement['checker']}`; evidence: `{requirement['evidence_ref']}`",
            "", "> " + requirement["statement"].replace("\n", "\n> "), "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
