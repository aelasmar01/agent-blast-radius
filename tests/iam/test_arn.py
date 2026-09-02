import pytest

from agent_blast_radius.iam.arn import Arn, matches, overlaps, subsumes

ROLE = "arn:aws:iam::000000000000:role/incident-response-role"


def test_parse():
    a = Arn.parse(ROLE)
    assert (a.partition, a.service, a.region, a.account) == ("aws", "iam", "", "000000000000")
    assert a.resource == "role/incident-response-role"


def test_parse_rejects_non_arn():
    with pytest.raises(ValueError):
        Arn.parse("not-an-arn")


@pytest.mark.parametrize(
    ("pattern", "arn", "expected"),
    [
        ("*", ROLE, True),
        ("arn:aws:iam::000000000000:role/*", ROLE, True),
        ("arn:aws:iam::111111111111:role/*", ROLE, False),  # same-account only
        ("arn:aws:iam::*:role/*", ROLE, True),
        ("arn:aws:iam::000000000000:role/incident-*", ROLE, True),
        ("arn:aws:iam::000000000000:role/incident-response-rol?", ROLE, True),
        ("arn:aws:iam::000000000000:user/*", ROLE, False),
        ("arn:aws:s3:::support-tickets/*", "arn:aws:s3:::support-tickets/t/1.json", True),
        ("arn:aws:s3:::support-tickets/*", "arn:aws:s3:::support-tickets", False),
        (
            "arn:aws:s3:::support-tickets/*",
            "arn:aws:s3:::Support-Tickets/x",
            False,
        ),  # case-sensitive
        ("arn:aws:s3:::*", "arn:aws:s3:::support-tickets/x", True),
    ],
)
def test_matches(pattern, arn, expected):
    assert matches(pattern, arn) is expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("*", "arn:aws:s3:::x/*", True),
        ("arn:aws:s3:::x/*", "*", False),
        ("arn:aws:s3:::x/*", "arn:aws:s3:::x/*", True),
        ("arn:aws:s3:::x/*", "arn:aws:s3:::x/y", True),
        ("arn:aws:s3:::x/*", "arn:aws:s3:::x/y/*", True),  # prefix-glob subsumes longer prefix-glob
        ("arn:aws:s3:::x/y/*", "arn:aws:s3:::x/*", False),
        ("arn:aws:iam::000000000000:role/*", "arn:aws:iam::000000000000:role/foo", True),
        ("arn:aws:iam::000000000000:role/*", "arn:aws:iam::111111111111:role/foo", False),
    ],
)
def test_subsumes(a, b, expected):
    assert subsumes(a, b) is expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("*", "arn:aws:s3:::x", True),
        ("arn:aws:s3:::secret-*/*", "arn:aws:s3:::*", True),
        ("arn:aws:s3:::secret-*/*", "arn:aws:s3:::public-*/*", False),
        ("arn:aws:s3:::a", "arn:aws:s3:::b", False),
        ("arn:aws:iam::000000000000:role/*", "arn:aws:iam::111111111111:role/*", False),
    ],
)
def test_overlaps(a, b, expected):
    assert overlaps(a, b) is expected
