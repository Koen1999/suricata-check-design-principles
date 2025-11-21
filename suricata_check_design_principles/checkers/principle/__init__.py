"""The `suricata_check_design_principles.checkers.principle` modules contains several checkers.

Based on the Ruling the Unruly paper.

Reference: https://koen.teuwen.net/publication/ruling-the-unruly
"""

from suricata_check.checkers.interface.dummy import DummyChecker

from suricata_check_design_principles.checkers.principle._principle import (
    PrincipleChecker,
)

try:
    from suricata_check_design_principles.checkers.principle._ml import PrincipleMLChecker  # type: ignore reportAssignmentType
except ImportError:

    class PrincipleMLChecker(DummyChecker):
        """Dummy class to prevent runtime errors on import."""


__all__ = [
    "PrincipleChecker",
    "PrincipleMLChecker",
]
