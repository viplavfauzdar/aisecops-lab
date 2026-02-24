from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import re
import yaml
import os
import threading

@dataclass
class ToolRule:
    name: str
    allow: bool = True
    allowed_params: Optional[List[str]] = None
    deny_patterns: Optional[Dict[str, str]] = None  # param -> regex

class PolicyEngine:
    def __init__(self, cfg: Dict[str, Any], path: Optional[str] = None):
        self._path = path
        self._lock = threading.RLock()
        self._last_mtime: Optional[float] = None
        self._last_reload_error: Optional[str] = None
        self.cfg = cfg or {}
        self.user_sanitize_patterns = [re.compile(p, re.IGNORECASE) for p in self.cfg.get("user_sanitize_regex", [])]
        self.tool_rules = self._load_tool_rules(self.cfg.get("tools", []))
        # RAG policy (Secure RAG controls)
        self._rag_cfg = self.cfg.get("rag", {}) or {}
        # Output policy (LLM response validation controls)
        self._output_cfg = self.cfg.get("output", {}) or {}

    @staticmethod
    def from_file(path: str) -> "PolicyEngine":
        cfg = PolicyEngine._load_cfg_from_path(path)
        pe = PolicyEngine(cfg, path=path)
        try:
            pe._last_mtime = os.path.getmtime(path)
        except OSError as e:
            pe._last_reload_error = str(e)
        return pe

    @staticmethod
    def _load_cfg_from_path(path: str) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _apply_cfg(self, cfg: Dict[str, Any]) -> None:
        """Apply config to this instance (recompute compiled patterns)."""
        self.cfg = cfg or {}
        self.user_sanitize_patterns = [re.compile(p, re.IGNORECASE) for p in self.cfg.get("user_sanitize_regex", [])]
        self.tool_rules = self._load_tool_rules(self.cfg.get("tools", []))
        self._rag_cfg = self.cfg.get("rag", {}) or {}
        self._output_cfg = self.cfg.get("output", {}) or {}

    def _reload_if_needed(self) -> None:
        """Hot-reload policy file when mtime changes. Fail-safe: keep last-known-good on errors."""
        if not self._path:
            return

        try:
            mtime = os.path.getmtime(self._path)
        except OSError as e:
            # File missing/unreadable; do not change current policy.
            self._last_reload_error = str(e)
            return

        with self._lock:
            if self._last_mtime is not None and mtime == self._last_mtime:
                return

            try:
                cfg = self._load_cfg_from_path(self._path)
                self._apply_cfg(cfg)
                self._last_mtime = mtime
                self._last_reload_error = None
            except Exception as e:
                # Keep old config.
                self._last_reload_error = str(e)
                return

    def last_reload_error(self) -> Optional[str]:
        """If hot-reload failed, returns the last error string (otherwise None)."""
        return self._last_reload_error

    def sanitize_user_text(self, text: str) -> str:
        self._reload_if_needed()
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
        self._reload_if_needed()
        rule = self.tool_rules.get(tool_name)
        if rule is None:
            # default deny unknown tools
            return False
        return rule.allow

    def validate_tool_params(self, tool_name: str, params: Dict[str, Any]) -> List[str]:
        self._reload_if_needed()
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
        self._reload_if_needed()
        return self._rag_cfg or {}

    def rag_sanitize_retrieval_enabled(self) -> bool:
        """Whether retrieval sanitization is enabled for Secure RAG."""
        self._reload_if_needed()
        return bool((self._rag_cfg or {}).get("sanitize_retrieval", False))

    def rag_deny_patterns(self) -> List[str]:
        """Regex patterns used to drop/neutralize instruction-like retrieved content."""
        self._reload_if_needed()
        pats = (self._rag_cfg or {}).get("deny_patterns", [])
        if not isinstance(pats, list):
            return []
        return [str(p) for p in pats if str(p).strip()]

    # ---- Output policy helpers ----
    def output_cfg(self) -> Dict[str, Any]:
        """Return the raw output policy config dict (may be empty)."""
        self._reload_if_needed()
        return self._output_cfg or {}

    def output_require_citations(self) -> bool:
        """Whether model replies must include at least one [S#] citation."""
        self._reload_if_needed()
        return bool((self._output_cfg or {}).get("require_citations", False))

    def output_forbidden_substrings(self) -> List[str]:
        """Substrings that should cause the model output to be blocked/refused."""
        self._reload_if_needed()
        subs = (self._output_cfg or {}).get("forbidden_substrings", [])
        if not isinstance(subs, list):
            return []
        return [str(s) for s in subs if str(s).strip()]
