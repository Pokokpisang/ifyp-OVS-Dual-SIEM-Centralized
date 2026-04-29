"""
Rule loader module for loading YAML detection rules.
"""
import yaml
from pathlib import Path
from typing import List, Dict, Optional
from ..schemas.rule_schema import DetectionRule

class RuleLoader:
    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path or Path(__file__).parent.parent / "rules"
        self.errors: List[Dict[str, str]] = []

    def load_rule_file(self, path: Path) -> Optional[DetectionRule]:
        """
        Load a single YAML file and validate it using DetectionRule schema.
        """
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            
            if data is None:
                raise ValueError("YAML file is empty")
                
            return DetectionRule(**data)
        except Exception as e:
            self.errors.append({
                "file": str(path),
                "error": str(e)
            })
            return None

    def load_rules_from_directory(self, directory: Path, include_disabled: bool = False) -> List[DetectionRule]:
        """
        Recursively find all .yaml and .yml files and validate them.
        """
        rules = []
        if not directory.exists():
            self.errors.append({
                "file": str(directory),
                "error": "Directory does not exist"
            })
            return rules

        for path in directory.rglob("*"):
            if path.suffix.lower() in [".yaml", ".yml"]:
                rule = self.load_rule_file(path)
                if rule:
                    if include_disabled or rule.enabled:
                        rules.append(rule)
        return rules

    def load_all_rules(self) -> List[DetectionRule]:
        """
        Load all rules from the default rules path.
        """
        return self.load_rules_from_directory(self.rules_path)
