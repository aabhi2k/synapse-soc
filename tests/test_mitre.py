"""
Tests that every MITRE technique ID hard-coded anywhere in the project
exists in the real ATT&CK catalog loaded at startup from STIX 2.1 data.
"""

import re
import unittest
from pathlib import Path

from engine.mitre_mapper import TECHNIQUE_CATALOG


class TestMitreMapper(unittest.TestCase):

    def test_catalog_is_populated(self):
        """Catalog must contain several hundred real techniques after STIX parse."""
        self.assertGreater(
            len(TECHNIQUE_CATALOG), 200,
            f"Expected > 200 techniques, got {len(TECHNIQUE_CATALOG)}"
        )

    def test_all_used_technique_ids_exist(self):
        """Every quoted technique ID (e.g. \"T1046\") used in source files must
        be present in the real ATT&CK catalog.  The test file itself is excluded
        so placeholder strings in comments/docstrings don't cause false-positives."""
        project_root = Path(__file__).parent.parent
        # Regex matches string literals like "T1046" or "T1110.001"
        tech_id_pattern = re.compile(r'"(T\d{4}(?:\.\d{3})?)"')

        found_ids: set[str] = set()
        for p in project_root.rglob("*.py"):
            # Skip virtual-env, node_modules, pycache, and THIS test file
            skip_dirs = {"venv", ".venv", "node_modules", "__pycache__"}
            if any(part in skip_dirs for part in p.parts):
                continue
            if p.resolve() == Path(__file__).resolve():
                continue  # exclude self to avoid scanner picking up test literals
            text = p.read_text(encoding="utf-8", errors="ignore")
            found_ids.update(tech_id_pattern.findall(text))

        missing = [tid for tid in found_ids if tid not in TECHNIQUE_CATALOG]
        self.assertEqual(
            missing, [],
            f"Technique IDs used in code but missing from ATT&CK catalog: {missing}"
        )

    def test_tactic_weights_cover_all_tactics(self):
        """TACTIC_WEIGHTS must have an entry for every tactic in kill-chain order."""
        from engine.mitre_mapper import TACTIC_WEIGHTS, MITRE_TACTIC_ORDER
        for tactic in MITRE_TACTIC_ORDER:
            self.assertIn(tactic, TACTIC_WEIGHTS,
                          f"Tactic '{tactic}' missing from TACTIC_WEIGHTS")
            self.assertGreater(TACTIC_WEIGHTS[tactic], 0,
                               f"Weight for '{tactic}' must be positive")

    def test_later_tactics_have_higher_weights(self):
        """Impact tactic must outweigh Reconnaissance (kill-chain justification)."""
        from engine.mitre_mapper import TACTIC_WEIGHTS
        self.assertGreater(
            TACTIC_WEIGHTS["Impact"],
            TACTIC_WEIGHTS["Reconnaissance"],
            "Impact should have higher weight than Reconnaissance"
        )


if __name__ == "__main__":
    unittest.main()
