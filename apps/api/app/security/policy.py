from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import re
import yaml

@dataclass
class ToolRule:
    name: str
    allow: bool = True
    allowed_params: Optional[List[str]] = None
    deny_patterns: Optional[Dict[str, str]] = None  # param -> regex

class PolicyEngine:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg or {}
        self.user_sanitize_patterns = [re.compile(p, re.IGNORECASE) for p in self.cfg.get("user_sanitize_regex", [])]
        self.tool_rules = self._load_tool_rules(self.cfg.get("tools", []))

    @staticmethod
    def from_file(path: str) -> "PolicyEngine":
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return PolicyEngine(cfg)

    def sanitize_user_text(self, text: str) -> str:
        out = text
        for pat in self.user_sanitize_patterns:
            out = pat.sub("[REDACTED]", out)
        return out

    def _load_tool_rules(self, tools_cfg: List[Dict[str, Any]]) -> Dict[str, ToolRule]:
        rules: Dict[str, ToolRule] = {}
        for t in tools_cfg:
            rules[t["name"]] = ToolRule(
                name=t["name"],
                allow=bool(t.get("allow", True)),
                allowed_params=t.get("allowed_params"),
                deny_patterns=t.get("deny_patterns"),
            )
        return rules

    def is_tool_allowed(self, tool_name: str) -> bool:
        rule = self.tool_rules.get(tool_name)
        if rule is None:
            # default deny unknown tools
            return False
        return rule.allow

    def validate_tool_params(self, tool_name: str, params: Dict[str, Any]) -> List[str]:
        errs: List[str] = []
        rule = self.tool_rules.get(tool_name)
        if rule is None:
            return [f"Unknown tool: {tool_name}"]
        if rule.allowed_params is not None:
            extra = set(params.keys()) - set(rule.allowed_params)
            if extra:
                errs.append(f"Disallowed params: {sorted(extra)}")
        if rule.deny_patterns:
            for k, regex in rule.deny_patterns.items():
                if k in params and isinstance(params[k], str):
                    if re.search(regex, params[k], flags=re.IGNORECASE):
                        errs.append(f"Param '{k}' matched deny pattern")
        return errs
