from agent_blast_radius.iam import actions


def test_iam_star_includes_passrole():
    """The botocore regression: iam:PassRole is not an API operation and must still expand."""
    assert "iam:PassRole" in actions.expand("iam:*")


def test_s3_listbucket_is_a_known_action():
    assert actions.is_known("s3:ListBucket")
    assert not actions.is_known("s3:ListObjectsV2")  # an API operation, not an IAM action


def test_expand_is_case_insensitive_and_returns_canonical_casing():
    assert actions.expand("S3:getobject") == {"s3:GetObject"}
    assert "s3:GetObject" in actions.expand("s3:get*")
    assert "s3:ListBucket" not in actions.expand("s3:Get*")


def test_question_mark_wildcard():
    assert "iam:PassRole" in actions.expand("iam:Pass?ole")


def test_service_wildcard_matches_multiple_services():
    hits = actions.expand("lambda*:Invoke*")
    assert "lambda:InvokeFunction" in hits


def test_star_expands_to_everything():
    everything = actions.expand("*")
    assert len(everything) > 20000
    assert "iam:PassRole" in everything and "kms:Decrypt" in everything


def test_unknown_literal_action_is_preserved_not_dropped():
    assert actions.expand("newservice:DoThing") == {"newservice:DoThing"}
    assert not actions.is_known("newservice:DoThing")


def test_unknown_wildcard_expands_to_nothing():
    assert actions.expand("newservice:*") == frozenset()


def test_access_level_and_condition_keys():
    assert actions.access_level("iam:PassRole") == "P"
    assert "iam:PassedToService" in actions.condition_keys("iam:PassRole")


def test_dataset_version_is_pinned():
    assert len(actions.dataset_version()) == 40
