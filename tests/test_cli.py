from __future__ import annotations

import pytest

from agent_blast_radius.cli import EXIT_ERROR, EXIT_INCOMPLETE, main


def test_scan_reports_inventory_and_refuses_to_claim_success(capsys):
    assert main(["scan", "fixtures/overprivileged-agent"]) == EXIT_INCOMPLETE
    out, err = capsys.readouterr()
    assert "read_support_ticket" in out
    assert "gated:approval_required" in out
    # A security tool that exits clean while computing nothing is the silent
    # under-report this project exists to avoid.
    assert "analysis not implemented" in err


def test_scan_on_missing_deployment_errors(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    assert "no agent.yaml" in capsys.readouterr().err


def test_no_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit):
        main([])
