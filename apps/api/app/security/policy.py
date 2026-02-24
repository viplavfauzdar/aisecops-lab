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
        # RAG policy (Secure RAG controls)
        self._rag_cfg = self.cfg.get("rag", {}) or {}
        # Output policy (LLM response validation controls)
        self._output_cfg = self.cfg.get("output", {}) or {}

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

    # ---- RAG policy helpers ----
    def rag_cfg(self) -> Dict[str, Any]:
        """Return the raw RAG policy config dict (may be empty)."""
        return self._rag_cfg or {}

    def rag_sanitize_retrieval_enabled(self) -> bool:
        """Whether retrieval sanitization is enabled for Secure RAG."""
        return bool((self._rag_cfg or {}).get("sanitize_retrieval", False))

    def rag_deny_patterns(self) -> List[str]:
        """Regex patterns used to drop/neutralize instruction-like retrieved content."""
        pats = (self._rag_cfg or {}).get("deny_patterns", [])
        if not isinstance(pats, list):
            return []
        return [str(p) for p in pats if str(p).strip()]

    # ---- Output policy helpers ----
    def output_cfg(self) -> Dict[str, Any]:
        """Return the raw output policy config dict (may be empty)."""
        return self._output_cfg or {}

    def output_require_citations(self) -> bool:
        """Whether model replies must include at least one [S#] citation."""
        return bool((self._output_cfg or {}).get("require_citations", False))

    def output_forbidden_substrings(self) -> List[str]:
        """Substrings that should cause the model output to be blocked/refused."""
        subs = (self._output_cfg or {}).get("forbidden_substrings", [])
        if not isinstance(subs, list):
            return []
        return [str(s) for s in subs if str(s).strip()]
