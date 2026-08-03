"""A plugin with nothing wrong with it, which a host may still refuse.

Its paperwork is faultless and it declares exactly what it does. The only
question it raises is whether you want a plugin that deletes things, and that
question has no answer preflight can supply -- it is the host's to answer.

Run ``preflight demo`` and this loads. Run ``preflight demo --refuse
destructive`` and the tripwire below never prints, because the same manifest
met a host that had said no.
"""

print("  [janitor] top-level plugin code is executing")
