from .models import ReconFinding  # noqa: F401
from .parsers import parse_recon_file  # noqa: F401


def match_findings(*args, **kwargs):
    """Lazy re-export — avoids importing qdrant/sentence-transformers unless used."""
    from .matcher import match_findings as _mf

    return _mf(*args, **kwargs)
