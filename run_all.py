"""Temporary end-to-end runner (Member D) for testing B + C + D together.

Member A's CLI (main.py) should replace this. It must show the Computer Crimes
Act 1997 disclaimer, check the scope and handle the kill switch. The calls
this file makes are the ones main.py needs:

    result = run_full_scan(target, dry_run=..., stop_file=...)
    print_report(target, result["score"], result["notes"])
    save_report(target, result["score"], result["findings"], notes=result["notes"])
"""

import argparse
import sys

from modules.pipeline import is_local_target, run_full_scan
from modules.reporting import print_dry_run, print_report, save_report


def main():
    parser = argparse.ArgumentParser(description="Honeypot detector - test runner")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="target (default: 127.0.0.1)")
    parser.add_argument("--dry-run", action="store_true", help="show what would be checked, send nothing")
    parser.add_argument("--stop-file", help="stop the scan if this file appears")
    parser.add_argument("--i-am-authorised", action="store_true",
                        help="required for any target other than localhost")
    args = parser.parse_args()

    if not is_local_target(args.target) and not args.i_am_authorised:
        sys.exit("Refusing to scan a non-local target without --i-am-authorised. "
                 "Only scan systems you own or have written permission to test.")

    result = run_full_scan(args.target, dry_run=args.dry_run, stop_file=args.stop_file)

    if result["dry_run"]:
        print_dry_run(args.target, result["planned"])
        for note in result["notes"]:
            print("Note:", note)
        return

    print_report(args.target, result["score"], result["notes"])
    paths = save_report(args.target, result["score"], result["findings"], notes=result["notes"])
    print("\nSaved:", *paths, sep="\n  ")


if __name__ == "__main__":
    main()
