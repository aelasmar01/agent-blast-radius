"""Property tests for ARN matching.

The Deny path rests on two invariants that spot-checks do not establish:

* ``subsumes(a, b)`` claims *every* ARN matching ``b`` also matches ``a``. The resolver
  deletes a capability on the strength of that claim, so a false positive here is a
  silent under-report — the failure mode this whole project is organized against.
* ``overlaps`` decides whether a Deny is worth flagging. It must never say "no" when the
  patterns can in fact both match something.

Generated ARNs and patterns find the shapes hand-written cases miss.
"""

from __future__ import annotations

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from agent_blast_radius.iam.arn import matches, overlaps, subsumes

SEGMENT = st.text(alphabet="abcz0-", min_size=0, max_size=4)
GLOB_SEGMENT = st.one_of(
    SEGMENT, st.builds(lambda a, b: f"{a}*{b}", SEGMENT, SEGMENT), st.just("*")
)


def _arn(service, region, account, resource):
    return f"arn:aws:{service}:{region}:{account}:{resource}"


CONCRETE = st.builds(_arn, SEGMENT, SEGMENT, SEGMENT, SEGMENT)
PATTERN = st.one_of(
    st.just("*"), st.builds(_arn, GLOB_SEGMENT, GLOB_SEGMENT, GLOB_SEGMENT, GLOB_SEGMENT)
)


@settings(max_examples=400)
@given(a=PATTERN, b=PATTERN, arn=CONCRETE)
def test_subsumption_implies_containment(a, b, arn):
    """The invariant the Deny logic deletes capabilities on."""
    assume(subsumes(a, b))
    assume(matches(b, arn))
    assert matches(a, arn), f"{a!r} claims to subsume {b!r} but does not match {arn!r}"


@settings(max_examples=400)
@given(a=PATTERN, b=PATTERN, arn=CONCRETE)
def test_a_shared_match_implies_overlap(a, b, arn):
    """overlaps must never miss a real intersection: it gates whether a Deny is flagged."""
    assume(matches(a, arn) and matches(b, arn))
    assert overlaps(a, b), f"{a!r} and {b!r} both match {arn!r} but overlaps() said no"


@settings(max_examples=300)
@given(a=PATTERN, b=PATTERN)
def test_overlap_is_symmetric(a, b):
    assert overlaps(a, b) == overlaps(b, a)


@settings(max_examples=300)
@given(a=PATTERN)
def test_reflexivity(a):
    assert subsumes(a, a)
    assert overlaps(a, a)


@settings(max_examples=300)
@given(a=PATTERN, b=PATTERN)
def test_subsumption_implies_overlap(a, b):
    assume(subsumes(a, b))
    assert overlaps(a, b)


@settings(max_examples=300)
@given(arn=CONCRETE)
def test_star_is_the_top_element(arn):
    assert matches("*", arn)
    assert subsumes("*", arn)


@settings(max_examples=300)
@given(pattern=PATTERN, arn=CONCRETE)
def test_matching_a_concrete_arn_is_subsumption_of_it(pattern, arn):
    assert matches(pattern, arn) == subsumes(pattern, arn)
