"""ARN parsing and wildcard matching.

An ARN is six colon-separated fields: ``arn:partition:service:region:account:resource``.
The resource field may itself contain colons and slashes. Matching is field-wise with
``*`` and ``?``, and case-sensitive throughout — S3 is the only common service where
that is debatable, and bucket names are lowercase by construction.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import cache


@dataclass(frozen=True, slots=True)
class Arn:
    partition: str
    service: str
    region: str
    account: str
    resource: str

    @classmethod
    def parse(cls, text: str) -> Arn:
        parts = text.split(":", 5)
        if len(parts) != 6 or parts[0] != "arn":
            raise ValueError(f"not an ARN: {text!r}")
        return cls(*parts[1:])

    @property
    def fields(self) -> tuple[str, str, str, str, str]:
        return (self.partition, self.service, self.region, self.account, self.resource)


def is_arn(text: str) -> bool:
    return text.startswith("arn:") and text.count(":") >= 5


@cache
def _glob(pattern: str) -> re.Pattern[str]:
    return re.compile(fnmatch.translate(pattern))


def matches(pattern: str, arn: str) -> bool:
    """Does a ``Resource`` element pattern cover this concrete ARN?"""
    if pattern == "*":
        return True
    if not is_arn(pattern) or not is_arn(arn):
        return _glob(pattern).match(arn) is not None
    p, a = Arn.parse(pattern), Arn.parse(arn)
    return all(_glob(pf).match(af) is not None for pf, af in zip(p.fields, a.fields, strict=True))


def _field_subsumes(a: str, b: str) -> bool:
    """Does glob ``a`` cover every string glob ``b`` covers? Conservative: False when unsure."""
    if a == "*" or a == b:
        return True
    if not ("*" in b or "?" in b):
        return _glob(a).match(b) is not None
    # Both have wildcards. Handle the one shape that matters in practice: a is a
    # prefix-glob ("foo*") and b is a longer prefix-glob ("foobar*").
    if a.endswith("*") and "?" not in a and a.count("*") == 1:
        return b.startswith(a[:-1])
    return False


def subsumes(pattern_a: str, pattern_b: str) -> bool:
    """Does pattern A cover every ARN pattern B covers?

    Used to decide whether a Deny wipes out an Allow capability entirely. When this
    returns False but :func:`overlaps` returns True, the Deny is partial and the
    capability is kept with a flag rather than silently narrowed.
    """
    if pattern_a == "*" or pattern_a == pattern_b:
        return True
    if pattern_b == "*":
        return False
    if not is_arn(pattern_a) or not is_arn(pattern_b):
        return _field_subsumes(pattern_a, pattern_b)
    a, b = Arn.parse(pattern_a), Arn.parse(pattern_b)
    return all(_field_subsumes(af, bf) for af, bf in zip(a.fields, b.fields, strict=True))


def _field_overlaps(a: str, b: str) -> bool:
    """Could some string match both globs? Conservative: True when unsure."""
    if a == "*" or b == "*" or a == b:
        return True
    wa, wb = ("*" in a or "?" in a), ("*" in b or "?" in b)
    if not wa and not wb:
        return False
    if not wa:
        return _glob(b).match(a) is not None
    if not wb:
        return _glob(a).match(b) is not None
    # Both wildcarded: the literal prefixes and suffixes must be compatible.
    pa, pb = re.split(r"[*?]", a, maxsplit=1)[0], re.split(r"[*?]", b, maxsplit=1)[0]
    sa, sb = (
        re.split(r"[*?]", a[::-1], maxsplit=1)[0][::-1],
        re.split(r"[*?]", b[::-1], maxsplit=1)[0][::-1],
    )
    prefix_ok = pa.startswith(pb) or pb.startswith(pa)
    suffix_ok = sa.endswith(sb) or sb.endswith(sa)
    return prefix_ok and suffix_ok


def overlaps(pattern_a: str, pattern_b: str) -> bool:
    """Could any ARN match both patterns?"""
    if pattern_a == "*" or pattern_b == "*" or pattern_a == pattern_b:
        return True
    if not is_arn(pattern_a) or not is_arn(pattern_b):
        return _field_overlaps(pattern_a, pattern_b)
    a, b = Arn.parse(pattern_a), Arn.parse(pattern_b)
    return all(_field_overlaps(af, bf) for af, bf in zip(a.fields, b.fields, strict=True))
