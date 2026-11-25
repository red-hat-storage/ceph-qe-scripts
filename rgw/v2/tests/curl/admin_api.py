"""
Backward-compatible AdminOps API surface.

Implementation lives in ``v2.tests.rest.reusable``. Prefer importing
from ``v2.tests.rest import reusable`` in new tests.
"""

from v2.tests.rest.reusable import *  # noqa: F401,F403
from v2.tests.rest.reusable import __all__  # noqa: F401
