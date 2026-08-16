from .models import ReconFinding  # noqa: F401
from .parsers import parse_recon_file  # noqa: F401


def plan_from_findings(*args, **kwargs):
    """Lazy re-export — importing the planner pulls in SQLAlchemy and the
    graph, which callers that only need the parsers should not pay for."""
    from .planner import plan_from_findings as _plan

    return _plan(*args, **kwargs)
