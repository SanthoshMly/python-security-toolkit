import argparse

from log_parser.parser import parse_file, generate_summary


def main():

    # Create the parser
    parser = argparse.ArgumentParser(description="Apache/Nginx Security Log Analyzer")

    # Add the logfile argument, tells argpasre that user must provide a log file to analyze
    parser.add_argument("logfile", help="Path to Apache/Nginx access log")

    # optional argument to show only suspicious requests
    parser.add_argument(
        "--suspicious", action="store_true", help="Show only suspicious requests"
    )

    # optional argument to show requests from a specific IP
    parser.add_argument("--ip", help="Show requests from a specific IP")

    args = parser.parse_args()

    entries = parse_file(args.logfile)

    # Filter by IP
    if args.ip:
        entries = [entry for entry in entries if entry["ip"] == args.ip]

    # Show suspicious requests
    if args.suspicious:

        entries = [entry for entry in entries if entry["suspicious"]]

        for entry in entries:
            print(
                f"{entry['ip']} "
                f"{entry['method']} "
                f"{entry['path']} "
                f"{entry['status']} "
                f"{entry['reasons']} "
            )

        return

    # Normal summary

    summary = generate_summary(entries)

    for ip, data in summary.items():

        print(f"\nIP: {ip}")
        print(f"Total requests: {data['total_requests']}")

        print("Status codes:")

        for status, count in sorted(data["status_codes"].items()):
            print(f" {status}: {count}")

        print(f"Suspicious requests: " f"{data['suspicious_requests']}")


if __name__ == "__main__":
    main()
