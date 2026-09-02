"""Terminal rendering. Reads the report dict, never the IR, so JSON and screen agree."""

from __future__ import annotations

from collections import Counter

#: Actions worth calling out by name even when no fail_if policy names them.
WATCHLIST = (
    "iam:*",
    "sts:AssumeRole",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
)


def _match(pattern: str, action: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def render(report: dict, *, watchlist: tuple[str, ...] = WATCHLIST) -> str:
    out: list[str] = []
    p = out.append

    account = report["account_id"] or "?"
    p(f"agent-blast-radius  deployment={report['deployment']}  account={account}")
    p(
        f"  report schema {report['schema_version']}  "
        f"dataset {report['dataset_version'][:12]}  rules v{report['rules_version']}"
    )
    p("")

    p("TOOLS")
    for t in report["tools"]:
        mark = "reachable  " if t["reachable"] else "unreachable"
        p(f"  {mark}  {t['name']:<24} role={t['role']:<24} {t['reason']}")
    p("")

    p("PRINCIPALS REACHABLE FROM ATTACKER INPUT")
    for role, depth in report["principals"].items():
        how = (
            "taint-reachable"
            if depth == 0
            else f"via {depth} escalation hop{'s' if depth > 1 else ''}"
        )
        p(f"  depth {depth}  {role:<28} {how}")
    p("")

    if report["account_admin"]:
        a = report["account_admin"]
        p("ACCOUNT TAKEOVER")
        p(f"  {a['title']}  [{a['rule']}, {a['source']}]  depth {a['depth']}")
        for line in a["path"]:
            p(f"    {line}")
        p("")

    chains = [c for c in report["escalation_chains"] if c["grants"] != "all_actions"]
    p(f"ESCALATION CHAINS ({len(chains)})")
    if not chains:
        p("  none")
    for c in chains:
        flag = "  [flagged]" if c["flagged"] else ""
        cite = f"[{c['rule']}, {c['source']}]"
        p(f"  -> {c['grants']}  via {c['title']}  {cite}  depth {c['depth']}{flag}")
        for line in c["path"]:
            p(f"       {line}")
    p("")

    caps = report["reachable_capabilities"]
    p(f"REACHABLE CAPABILITIES ({len(caps)})")
    by_principal: dict[str, list[dict]] = {}
    for c in caps:
        by_principal.setdefault(c["principal"], []).append(c)
    for principal, entries in by_principal.items():
        levels = Counter(e["access_level"] for e in entries)
        services = Counter(e["action"].split(":", 1)[0] for e in entries)
        top = ", ".join(f"{s}:{n}" for s, n in services.most_common(4))
        p(
            f"  {principal}: {len(entries)} capabilities  "
            f"(P={levels.get('P', 0)} W={levels.get('W', 0)} R={levels.get('R', 0)} "
            f"L={levels.get('L', 0)} T={levels.get('T', 0)})  {top}"
        )
        notable = [e for e in entries if any(_match(w, e["action"]) for w in watchlist)]
        n_iam = sum(1 for x in entries if x["action"].startswith("iam:"))
        shown = 0
        seen: set[str] = set()
        for e in notable:
            collapse = e["action"].startswith("iam:") and n_iam > 20
            key = "iam:*" if collapse else e["action"]
            if key in seen:
                continue
            seen.add(key)
            label = f"iam:* ({n_iam} iam actions)" if collapse else e["action"]
            flag = "  [flagged: " + ", ".join(e["residue"]) + "]" if e["residue"] else ""
            p(f"      {label} on {e['resource']}  <- {', '.join(e['provenance'])}{flag}")
            shown += 1
            if shown >= 6:
                break
    p("")

    p(f"UNSUPPORTED ({len(report['unsupported'])})")
    if not report["unsupported"]:
        p("  none — the analysis is complete for the constructs this tool models")
    for u in report["unsupported"]:
        detail = f": {u['detail']}" if u["detail"] else ""
        p(f"  {u['kind']}  {u['role']}/{u['policy']}#{u['sid']}{detail}")
    p("")

    if report["assumptions"]:
        p(f"ASSUMPTIONS ({len(report['assumptions'])})")
        for a in report["assumptions"]:
            p(f"  {a['kind']}  {a['role']}/{a['policy']}#{a['sid']}")
            p(f"    {a['detail']}")
        p("")

    if report["notices"]:
        p("NOTICES")
        for n in report["notices"]:
            p(f"  {n}")
        p("")

    p("Reachability is not exploitability: this is what the tool graph permits if the model")
    p("can be induced to make the calls, not a prediction that it will.")
    return "\n".join(out)
