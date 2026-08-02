"""A plugin that is exactly what its manifest says it is.

The print below is a tripwire. It is the earliest code in this package that can
possibly run, and it runs only if preflight decided this plugin was allowed to
be imported. Compare with ``collider``, whose identical line never appears in
the output of ``examples/host.py``.
"""

print("  [greeter] top-level plugin code is executing")
