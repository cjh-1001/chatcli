"""Concise status summaries for completed tool calls."""


class AgentToolSummaryMixin:
    def _tool_result_summary(self, name: str, result, elapsed: float) -> str:
        """Build a concise status line for a completed tool call."""
        parts = []
        meta = getattr(result, "metadata", {}) or {}
        if name == "bash":
            if "exit_code" in meta:
                parts.append(f"exit={meta['exit_code']}")
        elif name == "read_file":
            lines = meta.get("lines")
            total = meta.get("total_lines")
            if lines is not None and total is not None:
                parts.append(f"read {lines}/{total} lines")
        elif name in ("grep", "glob", "list_dir"):
            if "count" in meta:
                noun = "entries" if name == "list_dir" else "results"
                parts.append(f"{meta['count']} {noun}")
            if "files_searched" in meta:
                parts.append(f"searched {meta['files_searched']} files")
        elif name == "write_file":
            if "size" in meta:
                parts.append(f"{meta['size']} bytes")
        elif name == "edit_file":
            parts.append("edited")
        elif name == "multi_edit":
            if "edits" in meta:
                parts.append(f"{meta['edits']} edits")
        elif name == "web_search":
            if "count" in meta:
                parts.append(f"{meta['count']} results")
            if "backend" in meta:
                parts.append(f"backend={meta['backend']}")
        elif name == "web_fetch":
            if "content_length" in meta:
                parts.append(f"{meta['content_length']} chars")
            if meta.get("truncated"):
                parts.append("truncated")
        elif name == "git_status":
            if "changed" in meta:
                parts.append(f"{meta['changed']} changed")
        elif name == "git_diff":
            if "chars" in meta:
                parts.append(f"{meta['chars']} chars")
            if meta.get("staged"):
                parts.append("staged")
            if meta.get("truncated"):
                parts.append("truncated")
        elif name == "binary_inspect":
            if "format" in meta:
                parts.append(str(meta["format"]))
            if "size" in meta:
                parts.append(f"{meta['size']} bytes")
            if "imports" in meta:
                parts.append(f"{meta['imports']} imports")
            if "strings" in meta:
                parts.append(f"{meta['strings']} strings")
        elif name == "binary_find":
            matches = meta.get("matches")
            if isinstance(matches, list):
                parts.append(f"{len(matches)} matches")
                if matches:
                    parts.append("first=0x%x" % int(matches[0]))
            if meta.get("truncated"):
                parts.append("truncated")
        elif name == "binary_hexdump":
            if "offset" in meta:
                parts.append("off=0x%x" % int(meta["offset"]))
            if "length" in meta:
                parts.append(f"{meta['length']} bytes")
        elif name == "ida_analyze":
            if "entry_analysis_order" in meta:
                parts.append(f"{meta['entry_analysis_order']} entry-order")
            if "candidate_functions" in meta:
                parts.append(f"{meta['candidate_functions']} candidates")
            if "functions" in meta:
                parts.append(f"{meta['functions']} funcs")
            if "imports" in meta:
                parts.append(f"{meta['imports']} imports")
            if "strings" in meta:
                parts.append(f"{meta['strings']} strings")
            if "pseudocode" in meta:
                parts.append(f"{meta['pseudocode']} pseudocode")
        elif name == "ida_focus_decompile":
            if "targets" in meta:
                parts.append(f"{meta['targets']} targets")
            if "pseudocode" in meta:
                parts.append(f"{meta['pseudocode']} pseudocode")
            if "strings" in meta:
                parts.append(f"{meta['strings']} strings")
            if "calls" in meta:
                parts.append(f"{meta['calls']} calls")
            if "errors" in meta and meta["errors"]:
                parts.append(f"{meta['errors']} errors")
        elif name == "ida_deobfuscate":
            if "flattened_candidates" in meta:
                parts.append(f"{meta['flattened_candidates']} flattened")
            if "opaque_predicates" in meta:
                parts.append(f"{meta['opaque_predicates']} opaque")
            if "junk_instructions" in meta:
                parts.append(f"{meta['junk_instructions']} junk")
            if "function_maps" in meta:
                parts.append(f"{meta['function_maps']} maps")
            if "pseudocode" in meta:
                parts.append(f"{meta['pseudocode']} pseudocode")
            if meta.get("patched_database"):
                parts.append("patched-idb")
        elif name == "encoded_string_extract":
            if "plain_strings" in meta:
                parts.append(f"{meta['plain_strings']} plain")
            if "decoded_strings" in meta:
                parts.append(f"{meta['decoded_strings']} decoded")
            if "xor_strings" in meta:
                parts.append(f"{meta['xor_strings']} xor")
            if meta.get("output_json_path"):
                parts.append(str(meta["output_json_path"]))
        elif name == "obfuscated_data_map":
            if "suspicious_sections" in meta:
                parts.append(f"{meta['suspicious_sections']} sections")
            if "high_entropy_regions" in meta:
                parts.append(f"{meta['high_entropy_regions']} entropy")
            if "magic_hits" in meta:
                parts.append(f"{meta['magic_hits']} magic")
            if "xor_magic_hits" in meta:
                parts.append(f"{meta['xor_magic_hits']} xor-magic")
            if "constants" in meta:
                parts.append(f"{meta['constants']} constants")
        elif name == "reverse_technique_map":
            recommended = meta.get("recommended") or []
            if recommended:
                parts.append(f"{len(recommended)} routes")
        elif name == "reverse_evidence_map":
            if "files" in meta:
                parts.append(f"{meta['files']} files")
            if "matched_imports" in meta:
                parts.append(f"{meta['matched_imports']} imports")
            if "matched_strings" in meta:
                parts.append(f"{meta['matched_strings']} strings")
            if "candidate_functions" in meta:
                parts.append(f"{meta['candidate_functions']} candidates")
            if "pseudocode_hits" in meta:
                parts.append(f"{meta['pseudocode_hits']} pseudocode")
            if "function_maps" in meta:
                parts.append(f"{meta['function_maps']} maps")
        elif name == "runtime_string_hooks":
            if meta.get("frida_script"):
                parts.append(str(meta["frida_script"]))
            api_names = meta.get("api_names") or []
            if api_names:
                parts.append(f"{len(api_names)} api hooks")
        elif name == "external_static_analyze":
            if "ran" in meta:
                parts.append(f"{meta['ran']} analyzers")
            if meta.get("missing"):
                parts.append(f"missing={','.join(meta['missing'])}")
        elif name == "yara_scan":
            if "exit_code" in meta:
                parts.append(f"exit={meta['exit_code']}")
        elif name == "upx_unpack":
            if "created" in meta:
                parts.append("created" if meta["created"] else "no output")
            if "output" in meta:
                parts.append(str(meta["output"]))
        parts.append(self._fmt_time(elapsed))
        return " | ".join(str(p) for p in parts if p is not None)

