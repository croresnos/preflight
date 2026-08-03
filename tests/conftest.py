"""Keep imported test plugins from leaking between tests.

Several tests write a real, importable plugin package into ``tmp_path`` and let
preflight import it. Those modules stay in ``sys.modules`` afterwards, and the
folder names repeat across tests, so without this a later test importing
``widget`` would silently get the previous test's module -- and then fail the
loader's post-import ``__file__`` check for a reason that has nothing to do with
what it was testing.

Only modules loaded from pytest's temporary directory are removed. Anything else
is left alone.
"""

from __future__ import annotations

import sys

import pytest


@pytest.fixture(autouse=True)
def _forget_modules_imported_from_tmp_path(tmp_path_factory):
    yield
    root = str(tmp_path_factory.getbasetemp()).lower()
    for name, module in list(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if origin and str(origin).lower().startswith(root):
            del sys.modules[name]
