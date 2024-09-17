#!/usr/bin/env python3
import json
import sys
import glob
import os

# ANSI color codes
RESET = '\033[0m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
MAGENTA = '\033[35m'

def get_color_for_status(status):
    if 200 <= status < 300:
        return GREEN  # Success - Green
    elif 300 <= status < 400:
        return YELLOW  # Redirection - Yellow
    elif 400 <= status < 500:
        return RED  # Client Error - Red
    elif 500 <= status < 600:
        return MAGENTA  # Server Error - Magenta
    else:
        return RESET  # Default terminal color

def parse_ffuf_json(json_files):
    for json_file in json_files:
        if not os.path.isfile(json_file):
            continue
        with open(json_file, 'r') as f:
            data = json.load(f)
            results = data.get('results', [])
            if results:
                print(f"\nResults from {json_file}:")
                for result in results:
                    url = result.get('url')
                    status = result.get('status')
                    lines = result.get('lines')
                    color = get_color_for_status(status)
                    print(f"{url} {color}{status}{RESET} {lines}")
            else:
                print(f"\nNo results found in {json_file}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_ffuf_output.py <ffuf_output.json> [more_json_files...]")
        sys.exit(1)
    json_files = []
    for arg in sys.argv[1:]:
        # Expand glob patterns
        json_files.extend(glob.glob(arg))
    if not json_files:
        print("No JSON files found.")
        sys.exit(1)
    parse_ffuf_json(json_files)
