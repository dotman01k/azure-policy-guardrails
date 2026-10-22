import argparse
import json
from pathlib import Path
import sys
from .core import compile_templates, compile_exemption, compliance_report


def main():
    parser = argparse.ArgumentParser(description="Compile and inspect Azure Policy governance artifacts")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "exemption"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--config", default="config.json")
        cmd.add_argument("--subscription", required=True)
        cmd.add_argument("--resource-group", required=True)
        cmd.add_argument("--output", default="build")
        if name == "build":
            cmd.add_argument("--effect", choices=("Audit", "Deny"), default="Audit")
        else:
            for field in ("name", "expires-on", "ticket", "reason"):
                cmd.add_argument(f"--{field}", required=True)
            cmd.add_argument("--references", nargs="+", required=True)
    report = commands.add_parser("report")
    report.add_argument("--input", required=True)
    report.add_argument("--assignment-id", required=True)
    report.add_argument("--fail-on-noncompliance", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "report":
            result = compliance_report(json.loads(Path(args.input).read_text()), args.assignment_id)
            print(json.dumps(result, indent=2))
            return 2 if args.fail_on_noncompliance and (result["nonCompliantRecords"] or result["unknownRecords"]) else 0
        config = json.loads(Path(args.config).read_text())
        if args.command == "build":
            artifacts = compile_templates(config, args.subscription, args.resource_group, args.effect)
        else:
            artifacts = {"exemption.json": compile_exemption(config, args.subscription, args.resource_group,
                         args.name, args.references, args.expires_on, args.ticket, args.reason)}
        destination = Path(args.output)
        destination.mkdir(parents=True, exist_ok=True)
        for name, artifact in artifacts.items():
            (destination / name).write_text(json.dumps(artifact, indent=2) + "\n")
        print(f"Wrote {len(artifacts)} artifacts to {destination}")
        return 0
    except (ValueError, OSError, TypeError, KeyError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
