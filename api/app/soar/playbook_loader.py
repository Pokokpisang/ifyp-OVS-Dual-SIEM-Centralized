from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import ValidationError

from .schemas import SOARPlaybook


class PlaybookLoader:
    def __init__(self, playbooks_path: Optional[Path] = None):
        self.playbooks_path = playbooks_path or Path(__file__).parent / "playbooks"
        self.errors: List[Dict[str, str]] = []

    def load_playbook_file(self, path: Path) -> Optional[SOARPlaybook]:
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            return SOARPlaybook(**data)
        except (ValidationError, Exception) as exc:
            self.errors.append({"file": str(path), "error": str(exc)})
            return None

    def load_all_playbooks(self, include_disabled: bool = False) -> List[SOARPlaybook]:
        self.errors = []
        playbooks: List[SOARPlaybook] = []

        if not self.playbooks_path.exists():
            return playbooks

        for path in sorted(self.playbooks_path.rglob("*.yaml")):
            playbook = self.load_playbook_file(path)
            if playbook is None:
                continue
            if not playbook.enabled and not include_disabled:
                continue
            playbooks.append(playbook)

        for path in sorted(self.playbooks_path.rglob("*.yml")):
            playbook = self.load_playbook_file(path)
            if playbook is None:
                continue
            if not playbook.enabled and not include_disabled:
                continue
            playbooks.append(playbook)

        return playbooks
