"""Static blast-radius analysis for agentic systems running on AWS.

Computes the set of AWS actions reachable by an attacker who controls the model's
input, by propagating taint through an agent's tools and resolving the IAM policies
behind them. See README.md for the threat model and scope boundaries.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
