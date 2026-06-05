import unittest

from chatcli.tools.attack_chain import IMPACT_HINTS, STAGE_ORDER
from chatcli.tools.attack_technique_rules import HIGH_IMPACT, TECHNIQUE_MAP
from chatcli.tools.behavior_requirements import BEHAVIOR_REQUIREMENTS
from chatcli.tools.behavior_rules import CAPABILITY_RULES, CLAIM_GATES, STRONG_CLUSTERS
from chatcli.tools.behavior_hierarchy import CATEGORY_TO_FAMILY
from chatcli.tools.behavior_taxonomy import SPECIFIC_CATEGORY_OVERRIDES


ALL_CATEGORIES = set(CAPABILITY_RULES)


class BehaviorRuleIntegrityTests(unittest.TestCase):
    def test_requirement_categories_exist_and_terms_are_declared(self):
        for category, requirement in BEHAVIOR_REQUIREMENTS.items():
            self.assertIn(category, CAPABILITY_RULES, f"missing capability rule for {category}")
            declared_terms = {term.lower() for term in CAPABILITY_RULES[category]["terms"]}
            groups = requirement.get("groups") or {}
            self.assertTrue(groups, f"{category} has no requirement groups")
            for group_name, terms in groups.items():
                self.assertTrue(terms, f"{category}:{group_name} has no terms")
                missing = {term.lower() for term in terms} - declared_terms
                self.assertEqual(missing, set(), f"{category}:{group_name} has undeclared terms")

    def test_strong_clusters_and_claim_gates_reference_existing_rules(self):
        for category, terms in STRONG_CLUSTERS.items():
            self.assertIn(category, CAPABILITY_RULES, f"strong cluster references unknown {category}")
            declared_terms = {term.lower() for term in CAPABILITY_RULES[category]["terms"]}
            missing = {term.lower() for term in terms} - declared_terms
            self.assertEqual(missing, set(), f"{category} strong cluster has undeclared terms")

        for category in CLAIM_GATES:
            self.assertIn(category, CAPABILITY_RULES, f"claim gate references unknown {category}")

    def test_attack_chain_covers_all_capability_categories(self):
        missing_stage = ALL_CATEGORIES - set(STAGE_ORDER)
        missing_impact = ALL_CATEGORIES - set(IMPACT_HINTS)
        self.assertEqual(missing_stage, set(), "capability categories missing attack-chain stage")
        self.assertEqual(missing_impact, set(), "capability categories missing impact hint")

    def test_attack_mapping_and_high_impact_are_consistent(self):
        unknown_mappings = set(TECHNIQUE_MAP) - ALL_CATEGORIES
        self.assertEqual(unknown_mappings, set(), "ATT&CK map references unknown categories")

        missing_mapping = HIGH_IMPACT - set(TECHNIQUE_MAP)
        self.assertEqual(missing_mapping, set(), "high-impact categories missing ATT&CK mapping")

    def test_taxonomy_references_existing_categories(self):
        for general, specifics in SPECIFIC_CATEGORY_OVERRIDES.items():
            self.assertIn(general, CAPABILITY_RULES, f"taxonomy general category unknown: {general}")
            self.assertTrue(specifics, f"taxonomy general category has no specifics: {general}")
            missing = set(specifics) - ALL_CATEGORIES
            self.assertEqual(missing, set(), f"taxonomy references unknown specifics for {general}")

    def test_hierarchy_covers_all_capability_categories(self):
        missing = ALL_CATEGORIES - set(CATEGORY_TO_FAMILY)
        unknown = set(CATEGORY_TO_FAMILY) - ALL_CATEGORIES
        self.assertEqual(missing, set(), "capability categories missing hierarchy family")
        self.assertEqual(unknown, set(), "hierarchy references unknown capability categories")


if __name__ == "__main__":
    unittest.main()
