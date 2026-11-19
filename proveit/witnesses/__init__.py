"""Witness registry. ``builtin`` is imported explicitly so registration is static."""

from . import builtin
from .registry import all_witnesses, describe, get, register, result

__all__ = ["all_witnesses", "builtin", "describe", "get", "register", "result"]
