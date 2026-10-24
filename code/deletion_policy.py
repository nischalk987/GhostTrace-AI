"""Validated, deterministic deletion-policy evaluation.

Raw evidence classification and policy decisions are deliberately separate. Each
decision names the matched rule IDs, condition evaluation, precedence, and safe
action. Unknown/contradictory conditions fail closed: they never authorize deletion.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

REQUIRED_COLUMNS = ("rule_id", "data_category", "condition", "required_action")
ALLOWED_ACTIONS = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}
SUPPORTED_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
    "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
    "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE",
}
ACTION_PRECEDENCE = {"RETAIN": 0, "REDACT": 1, "ANONYMIZE": 2, "DELETE": 3}

class PolicyError(ValueError):
    """Raised when supplied deletion-policy rules are malformed or unsafe."""

@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str

@dataclass(frozen=True)
class PolicyDecision:
    data_category: str
    action: str
    rule_ids: tuple[str, ...]
    matched_rules: tuple[PolicyRule, ...]
    diagnostics: tuple[str, ...]
    rationale: str
    safe_to_delete: bool

    @property
    def rule_id(self) -> str:
        return self.rule_ids[0] if len(self.rule_ids) == 1 else ",".join(self.rule_ids)


def _truth(value: Any) -> bool:
    return value is True or str(value).strip().casefold() in {"1", "true", "yes", "active", "enabled"}


def _condition_result(rule: PolicyRule, context: Mapping[str, Any]) -> bool | None:
    condition = " ".join(rule.condition.casefold().split())
    ctx = {str(k).casefold(): v for k, v in context.items()}
    category = rule.data_category
    # Unconditional rules are explicit and do not require inferred facts.
    if condition == "always":
        return True
    if category == "SUPPORT_MESSAGE":
        # Shared conversation context must be retained, therefore redact direct PII.
        keys = ("shared_context_must_be_retained", "shared_customer_agent_order_context",
                "must_retain_shared_context")
        if any(k in ctx for k in keys):
            return any(_truth(ctx[k]) for k in keys if k in ctx)
        text = " ".join(str(v).casefold() for v in ctx.values())
        if "shared" in text and ("must be retained" in text or "must retain" in text):
            return True
        if text:
            return False
        return None
    if category == "SUPPORT_ATTACHMENT":
        for key in ("belongs_only_to_subject", "attachment_belongs_only_to_subject", "subject_only"):
            if key in ctx:
                return _truth(ctx[key])
        return None
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        for key in ("still_attributable", "attributable_to_user", "contains_direct_identifier", "directly_identifiable"):
            if key in ctx:
                return _truth(ctx[key])
        return None
    if category == "EMAIL_DELIVERY_LOG":
        for key in ("contains_user_email", "contains_email", "email_present"):
            if key in ctx:
                return _truth(ctx[key])
        return None
    if category == "SECURITY_AUDIT_LOG":
        for key in ("within_retention_period", "retention_active", "must_retain"):
            if key in ctx:
                return _truth(ctx[key])
        return None
    if category == "LEGAL_HOLD_RECORD":
        for key in ("legal_hold_active", "active_legal_hold", "has_active_legal_hold"):
            if key in ctx:
                return _truth(ctx[key])
        return None
    if category == "BACKUP_ARCHIVE":
        for key in ("restore_access_can_be_blocked", "restore_block_supported", "can_block_restore"):
            if key in ctx:
                return _truth(ctx[key])
        return None
    if category == "ACCOUNT_TOMBSTONE":
        # Direct PII is always forbidden here; stable user_id is the only allowed
        # identifying reference when retained-record linkage requires it.
        deleted = any(_truth(ctx[k]) for k in ("account_deleted", "deleted_account", "deletion_confirmed") if k in ctx)
        stable = any(_truth(ctx[k]) for k in ("stable_user_id_required", "stable_reference_required", "retained_record_references") if k in ctx)
        return deleted and stable
    # A non-empty but unrecognized condition must never be guessed true.
    return None


class DeletionPolicy:
    """Load rules from the supplied CSV and make explainable, fail-closed decisions."""
    def __init__(self, rules: Iterable[PolicyRule]):
        self.rules = tuple(rules)

    @classmethod
    def from_csv(cls, path: str | Path) -> "DeletionPolicy":
        path = Path(path)
        if not path.is_file():
            raise PolicyError(f"Deletion rules file is missing: {path}")
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise PolicyError(f"Deletion rules file has no header: {path}")
            missing = sorted(set(REQUIRED_COLUMNS) - set(reader.fieldnames))
            if missing:
                raise PolicyError(f"{path}: missing columns {', '.join(missing)}")
            rows = list(reader)
        if not rows:
            raise PolicyError(f"Deletion rules file has no rules: {path}")
        rules: list[PolicyRule] = []
        ids: set[str] = set()
        for line_no, row in enumerate(rows, start=2):
            rule_id = (row.get("rule_id") or "").strip()
            category = (row.get("data_category") or "").strip().upper()
            condition = " ".join((row.get("condition") or "").strip().split())
            action = (row.get("required_action") or "").strip().upper()
            if not rule_id or rule_id in ids:
                raise PolicyError(f"{path}:{line_no}: empty or duplicate rule_id {rule_id!r}")
            if not category:
                raise PolicyError(f"{path}:{line_no}: empty data_category")
            if category not in SUPPORTED_CATEGORIES:
                raise PolicyError(f"{path}:{line_no}: unsupported category {category!r}")
            if not condition:
                raise PolicyError(f"{path}:{line_no}: empty condition")
            if action not in ALLOWED_ACTIONS:
                raise PolicyError(f"{path}:{line_no}: unsupported required_action {action!r}")
            ids.add(rule_id)
            rules.append(PolicyRule(rule_id, category, condition, action))
        return cls(rules)

    def decide(self, category: str, context: Mapping[str, Any] | None = None) -> PolicyDecision:
        category = str(category or "").strip().upper()
        context = context or {}
        candidates = [rule for rule in self.rules if rule.data_category == category]
        matched: list[PolicyRule] = []
        unknown: list[PolicyRule] = []
        for rule in candidates:
            result = _condition_result(rule, context)
            if result is True:
                matched.append(rule)
            elif result is None:
                unknown.append(rule)
        diagnostics: list[str] = []
        if not candidates:
            return PolicyDecision(category, "UNRESOLVED", (), (), ("NO_APPLICABLE_RULE",),
                                  f"No supplied rule exists for {category or '<empty category>'}; no action is authorized.", False)
        if not matched and unknown:
            diagnostic = "UNRESOLVED_CONDITION:" + ",".join(rule.rule_id for rule in unknown)
            return PolicyDecision(category, "UNRESOLVED", tuple(rule.rule_id for rule in unknown),
                                  tuple(unknown), (diagnostic,),
                                  "Required condition could not be established from explicit evidence; no destructive action is authorized.", False)
        if not matched:
            return PolicyDecision(category, "NOT_APPLICABLE", (), (), (),
                                  "Supplied rule conditions were evaluated and none applied.", False)
        actions = {rule.required_action for rule in matched}
        # RETAIN always wins over destructive treatment. REDACT wins over DELETE
        # because it satisfies preservation while removing identifiers. Remaining
        # conflicts are surfaced rather than silently picking a rule.
        if "RETAIN" in actions:
            action = "RETAIN"
            diagnostics.append("RETENTION_PRECEDENCE")
        elif "REDACT" in actions and "DELETE" in actions:
            action = "REDACT"
            diagnostics.append("CONFLICT_REDACT_OVER_DELETE")
        elif len(actions) == 1:
            action = next(iter(actions))
        else:
            diagnostic = "CONTRADICTORY_POLICY_ACTIONS:" + ",".join(sorted(actions))
            return PolicyDecision(category, "UNRESOLVED", tuple(r.rule_id for r in matched),
                                  tuple(matched), (diagnostic,),
                                  "Applicable rules conflict without a safe defined precedence; no destructive action is authorized.", False)
        reasons = "; ".join(f"{r.rule_id}: {r.condition} => {r.required_action}" for r in sorted(matched, key=lambda r: r.rule_id))
        return PolicyDecision(category, action, tuple(r.rule_id for r in sorted(matched, key=lambda r: r.rule_id)),
                              tuple(sorted(matched, key=lambda r: r.rule_id)), tuple(diagnostics),
                              reasons, action == "DELETE")


def record_policy_category(path: str, store: str = "", collection: str = "", resource_id: str = "") -> str:
    """Map content location/type to a challenge policy category using specificity-first rules."""
    text = " ".join(str(x) for x in (path, store, collection, resource_id)).casefold()
    # Specific categories first: a tombstone must not become an ordinary profile,
    # and legal hold must outrank generic backup/archive naming.
    if "legal_hold" in text or "legal hold" in text or "legal_hold" in text:
        return "LEGAL_HOLD_RECORD"
    if "tombstone" in text or "deleted_customer_reference" in text:
        return "ACCOUNT_TOMBSTONE"
    if "security" in text or "audit_record" in text or "audit_ledger" in text:
        return "SECURITY_AUDIT_LOG"
    if "delivery" in text or "email_delivery" in text or "notification" in text:
        return "EMAIL_DELIVERY_LOG"
    if "attachment" in text:
        return "SUPPORT_ATTACHMENT"
    if "support" in text or "conversation" in text or "ticket" in text:
        return "SUPPORT_MESSAGE"
    if "telemetry" in text:
        return "PRODUCT_TELEMETRY"
    if "analytics" in text:
        return "ANALYTICS_PROFILE"
    if "search" in text:
        return "SEARCH_INDEX_ENTRY"
    if "cache" in text:
        return "CACHE_ENTRY"
    if "backup" in text or "restore" in text or "archive" in text or "failover" in text:
        return "BACKUP_ARCHIVE"
    if "export" in text or "object_store" in text:
        return "USER_EXPORT"
    if "marketing" in text:
        return "MARKETING_PROFILE"
    if "profile" in text or "account" in text:
        return "USER_PROFILE"
    return "SECONDARY_IDENTIFIER"
