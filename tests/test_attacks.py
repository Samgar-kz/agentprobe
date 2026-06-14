"""Tests for attack catalogue and transforms."""


from agentprobe.attacks import all_attacks
from agentprobe.attacks.base import Severity
from agentprobe.attacks.transforms import PRAGMATIC, REGISTER, DISCOURSE, CODESWITCH, CLASSIC


class TestTransformCategories:
    """Verify all transform categories are defined and have content."""

    def test_pragmatic_transforms_exist(self):
        """Pragmatic transforms should exist."""
        assert PRAGMATIC, "PRAGMATIC transforms list is empty"
        assert len(PRAGMATIC) >= 2

    def test_register_transforms_exist(self):
        """Register transforms should exist."""
        assert REGISTER, "REGISTER transforms list is empty"
        assert len(REGISTER) >= 2

    def test_discourse_transforms_exist(self):
        """Discourse transforms should exist."""
        assert DISCOURSE, "DISCOURSE transforms list is empty"
        assert len(DISCOURSE) >= 2

    def test_codeswitch_transforms_exist(self):
        """Codeswitch transforms should exist."""
        assert CODESWITCH, "CODESWITCH transforms list is empty"
        assert len(CODESWITCH) >= 1

    def test_classic_transforms_exist(self):
        """Classic transforms should exist."""
        assert CLASSIC, "CLASSIC transforms list is empty"
        assert len(CLASSIC) >= 1

    def test_transform_has_apply_function(self):
        """Each transform should have an apply function."""
        for transforms in [PRAGMATIC, REGISTER, DISCOURSE, CODESWITCH, CLASSIC]:
            for t in transforms:
                assert callable(t.apply), f"{t.name} missing apply function"
                assert t.category, f"{t.name} missing category"
                assert t.rationale, f"{t.name} missing rationale"

    def test_transforms_are_applicable(self):
        """Each transform should be able to transform text."""
        for transforms in [PRAGMATIC, REGISTER, DISCOURSE, CODESWITCH, CLASSIC]:
            for t in transforms:
                result = t.apply("test instruction")
                assert isinstance(result, str), f"{t.name} apply() should return string"
                assert len(result) > 0, f"{t.name} apply() returned empty string"


class TestAttackCatalogue:
    """Verify the attack catalogue is valid and comprehensive."""

    def test_all_attacks_returns_non_empty(self):
        """all_attacks() should return a non-empty list."""
        attacks = all_attacks()
        assert attacks, "all_attacks() returned empty list"
        assert len(attacks) >= 30, "expected at least 30 attacks in catalogue"

    def test_all_attacks_have_required_fields(self):
        """Each attack should have all required fields."""
        for attack in all_attacks():
            assert attack.id, "attack missing id"
            assert attack.category, "attack missing category"
            assert attack.severity, "attack missing severity"
            assert attack.description, "attack missing description"
            assert attack.payload, "attack missing payload"
            assert attack.success_signals is not None, "attack missing success_signals"
            assert isinstance(attack.success_signals, list), "success_signals should be list"

    def test_attack_ids_are_unique(self):
        """No duplicate attack IDs."""
        attacks = all_attacks()
        ids = [a.id for a in attacks]
        assert len(ids) == len(set(ids)), "duplicate attack IDs found"

    def test_attack_categories_are_valid(self):
        """All attacks should use known categories."""
        valid_cats = {"pragmatic", "register", "discourse", "codeswitch", "classic"}
        for attack in all_attacks():
            assert attack.category in valid_cats, f"unknown category: {attack.category}"

    def test_attack_severities_are_valid(self):
        """All attacks should have valid severity."""
        valid_sev = {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
        for attack in all_attacks():
            assert attack.severity in valid_sev, f"invalid severity: {attack.severity}"

    def test_attacks_by_category_balanced(self):
        """Attack catalogue should have reasonable distribution."""
        attacks = all_attacks()
        by_cat = {}
        for a in attacks:
            by_cat.setdefault(a.category, []).append(a)

        # Each category should have at least one attack
        for cat in {"pragmatic", "register", "discourse", "codeswitch", "classic"}:
            assert cat in by_cat, f"missing category: {cat}"
            assert len(by_cat[cat]) >= 1, f"category {cat} has no attacks"

    def test_attack_tool_fields_valid(self):
        """If tool-related fields are set, they should be consistent."""
        for attack in all_attacks():
            if attack.expected_tool_call:
                assert isinstance(attack.expected_tool_call, str)
            if attack.expected_tool_arg_contains:
                assert isinstance(attack.expected_tool_arg_contains, str)
            # If arg filter is set, tool call should also be set
            if attack.expected_tool_arg_contains:
                assert attack.expected_tool_call, "tool arg filter without tool call"


class TestAttackPayloads:
    """Verify attack payloads are well-formed."""

    def test_payload_is_string(self):
        """All payloads should be strings."""
        for attack in all_attacks():
            assert isinstance(attack.payload, str), f"{attack.id} payload not string"

    def test_payload_not_empty(self):
        """All payloads should have content."""
        for attack in all_attacks():
            assert len(attack.payload.strip()) > 0, f"{attack.id} payload is empty"

    def test_payload_reasonable_length(self):
        """Payloads shouldn't be excessively long."""
        for attack in all_attacks():
            # Allow up to 5000 chars for complex payloads
            assert len(attack.payload) <= 5000, f"{attack.id} payload suspiciously long"

    def test_success_signals_valid(self):
        """Success signals should be non-empty strings."""
        for attack in all_attacks():
            assert isinstance(attack.success_signals, list), f"{attack.id} success_signals not list"
            # Some attacks may have no signals if tool-based
            for signal in attack.success_signals:
                assert isinstance(signal, str), f"{attack.id} signal not string"
                assert len(signal) > 0, f"{attack.id} empty signal"


class TestAttackCounts:
    """Verify attack counts by category."""

    def test_pragmatic_count(self):
        """Should have several pragmatic attacks."""
        attacks = [a for a in all_attacks() if a.category == "pragmatic"]
        assert len(attacks) >= 5

    def test_register_count(self):
        """Should have several register attacks."""
        attacks = [a for a in all_attacks() if a.category == "register"]
        assert len(attacks) >= 5

    def test_discourse_count(self):
        """Should have several discourse attacks."""
        attacks = [a for a in all_attacks() if a.category == "discourse"]
        assert len(attacks) >= 5

    def test_codeswitch_count(self):
        """Should have some codeswitch attacks."""
        attacks = [a for a in all_attacks() if a.category == "codeswitch"]
        assert len(attacks) >= 1

    def test_classic_count(self):
        """Should have several classic attacks."""
        attacks = [a for a in all_attacks() if a.category == "classic"]
        assert len(attacks) >= 3
