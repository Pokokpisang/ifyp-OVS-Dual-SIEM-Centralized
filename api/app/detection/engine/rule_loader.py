"""
Rule loader module for loading YAML detection rules.
"""
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from ..schemas.rule_schema import DetectionRule

class RuleLoader:
    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path or Path(__file__).parent.parent / "rules"
        self.errors: List[Dict[str, str]] = []
        # Path -> (mtime, parsed rule). Only successful parses are cached, so a
        # file that fails validation is re-parsed (and re-reported) each call.
        self._cache: Dict[Path, Tuple[float, DetectionRule]] = {}

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

        Parsed rules are cached by file mtime, so unchanged files are not
        re-read on subsequent calls (this method runs on every detection event).
        Editing a file changes its mtime and transparently reloads it.
        ``self.errors`` is rebuilt on every call.
        """
        self.errors = []
        rules: List[DetectionRule] = []
        if not directory.exists():
            self.errors.append({
                "file": str(directory),
                "error": "Directory does not exist"
            })
            return rules

        seen: set = set()
        for path in directory.rglob("*"):
            if path.suffix.lower() not in (".yaml", ".yml"):
                continue
            seen.add(path)

            try:
                mtime = path.stat().st_mtime
            except OSError:
                rule = self.load_rule_file(path)  # records error
            else:
                cached = self._cache.get(path)
                if cached is not None and cached[0] == mtime:
                    rule = cached[1]
                else:
                    rule = self.load_rule_file(path)
                    if rule is not None:
                        self._cache[path] = (mtime, rule)
                    else:
                        self._cache.pop(path, None)

            if rule and (include_disabled or rule.enabled):
                rules.append(rule)

        # Evict cache entries for files that no longer exist.
        for stale in set(self._cache) - seen:
            self._cache.pop(stale, None)

        return rules

    def load_all_rules(self) -> List[DetectionRule]:
        """
        Load all rules from the default rules path.
        """
        return self.load_rules_from_directory(self.rules_path)
