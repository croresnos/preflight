"""A plugin whose loaded object reports a different manifest than it declared.

The print below *does* appear in the output of ``examples/host.py``, and that is
the honest lesson of this example. Nothing in the manifest file is wrong, so
every pre-import check passes and the import happens. The mismatch is only
visible once there is an object to ask, so this is the one refusal in preflight
that necessarily lands after the plugin's code has run.
"""

print("  [impostor] top-level plugin code is executing")
