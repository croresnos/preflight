"""A plugin that claims a tool name ``greeter`` already owns.

The print below never appears in the output of ``examples/host.py``. The tool
name collision is visible in the manifest file, so the refusal happens while this
package is still inert text on disk.
"""

print("  [collider] top-level plugin code is executing -- THIS SHOULD NEVER PRINT")
