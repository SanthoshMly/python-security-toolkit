import argparse

from log_parser.parser import parse_file, generate_summary


def main():

    # Create the parser
    parser = argparse.ArgumentParser(description="Apache/Nginx Security Log Analyzer")

    # Add the logfile argument, tells argpasre that user must provide a log file to analyze
    parser.add_argument("logfile", help="Path to Apache/Nginx access log")


if __name__ == "__main__":
    main()
