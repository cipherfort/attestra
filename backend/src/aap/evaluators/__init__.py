# SPDX-License-Identifier: Apache-2.0
"""Versioned control evaluators. Each is a pure function of (control, app, evidence, findings) → result."""

from aap.evaluators import library as _library  # noqa: F401  (registers evaluators)
from aap.evaluators.base import EvaluationInput, EvaluationResult, evaluate_control, registry

__all__ = ["EvaluationInput", "EvaluationResult", "evaluate_control", "registry"]
