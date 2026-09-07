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


if __name__ == "__main__":
    main()
