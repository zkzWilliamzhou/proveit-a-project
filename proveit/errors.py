"""Typed failures for proveit.

Design invariant: no exception in this module maps to ``PASS``. Any unexpected
failure is converted by the engine into ``UNVERIFIABLE`` with an explicit reason
code. A verification tool that degrades into approval is worse than no tool.
"""

from __future__ import annotations


class ProveitError(Exception):
    """Base class for every proveit failure."""


class PolicyViolation(ProveitError):
    """Input attempted to cross a trust boundary."""


class InputError(ProveitError):
    """Malformed or unusable input."""


class LimitExceeded(InputError):
    """A resource bound was hit."""


class UsageError(ProveitError):
    """The operator asked for something impossible or contradictory."""


class WitnessUnavailable(ProveitError):
    """A registered witness cannot run in this environment."""


class ExecutionError(ProveitError):
    """A child process could not be started or supervised."""


class StaleReceipt(ProveitError):
    """A receipt no longer describes the repository it was issued for."""
