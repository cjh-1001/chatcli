# chatcli IDA Scripts

These scripts are meant to be run inside IDA Pro with `File -> Script file...`
or copied into IDA's scripts/plugins workflow.

## chatcli_ai_context.py

Exports an AI-friendly snapshot of the current IDA database:

- metadata and entry/current function,
- current function pseudocode/disassembly,
- callers, callees, strings, comments, and xrefs,
- top scored candidate functions,
- interesting imports and strings.

Outputs both JSON and Markdown. Set these environment variables before
launching IDA to tune the export:

- `CHATCLI_IDA_EXPORT_DIR`: output directory.
- `CHATCLI_IDA_MAX_FUNCS`: candidate function limit, default `80`.
- `CHATCLI_IDA_INCLUDE_PSEUDOCODE`: `1` to include Hex-Rays pseudocode.
- `CHATCLI_IDA_MAX_DISASM`: max disassembly lines per focused function.

## chatcli_ai_apply.py

Applies reviewed AI suggestions to the IDB. Expected JSON:

```json
{
  "renames": [{"ea": "0x140001000", "name": "check_password"}],
  "comments": [{"ea": "0x140001020", "comment": "compares decoded input", "repeatable": false}],
  "colors": [{"ea": "0x140001000", "color": "0x66ccff"}]
}
```

The script shows a summary and asks for confirmation before modifying the IDB.

