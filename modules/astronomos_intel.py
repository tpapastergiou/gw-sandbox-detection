#read a list of IPs from a file and get the pdns records. Then use the astronomos api to get the intel for each IP
import dns.resolver
import dns.reversename
import subprocess
import argparse
import json
import os
from typing import Dict, Any
import time

ASTRONOMOS_QUERY_DELAY = float(os.getenv("ASTRONOMOS_QUERY_DELAY", "0.3"))  # seconds to wait between queries to avoid rate limits


def get_ptr_name(ip: str, timeout: float = 2.0) -> str | None:
    try:
        rev = dns.reversename.from_address(ip)  # builds in-addr.arpa / ip6.arpa name
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(rev, "PTR")
        # return first PTR target, without trailing dot
        return str(answers[0]).rstrip(".")
    except Exception:
        return None

def run_astronomos(ptr: str) -> Dict[str, Any]:
    cmd = ["astronomos-gr", "el", "ptr", ptr, "-o", "json"]

    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,  # handle errors ourselves so we can show stderr
    )

    if p.returncode != 0:
        raise RuntimeError(
            f"astronomos-gr failed (exit {p.returncode})\n"
            f"STDOUT:\n{p.stdout}\n"
            f"STDERR:\n{p.stderr}"
        )

    # If the tool prints exactly one JSON object, this works:
    return json.loads(p.stdout.strip())

# read IPs from file and get the pdns records. Then use the astronomos api to get the intel for each IP and write output to a file
def process_file(input_path: str, output_path: str) -> None:
    # Stream input line-by-line and write JSONL line-by-line (no full read into memory).
    #create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(input_path, "r", encoding="utf-8") as fin, open(output_path, "w", encoding="utf-8") as fout:
        for lineno, line in enumerate(fin, start=1):
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue

            ptr = get_ptr_name(ip)
            record = {
                "ip": ip,
                "ptr": ptr,  # null in JSON if None
                "has_ptr": ptr is not None,
                "astronomos_el_ptr": None, # to be filled if has_ptr is True
            }

            time.sleep(ASTRONOMOS_QUERY_DELAY)

            if record.get("has_ptr"):
                intel = run_astronomos(record["ptr"])
                record["astronomos_el_ptr"] = intel

            fout.write(json.dumps(record, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process IPs with Astronomos Intel")
    parser.add_argument("input_file", help="Path to input file containing IPs (one per line)")
    parser.add_argument("output_file", help="Path to output file for JSONL results")
    args = parser.parse_args()
    print(f"Starting {args.input_file}")
    process_file(args.input_file, args.output_file)
    print(f"Finished {args.input_file}")
