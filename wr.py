#!/usr/bin/env python3
import sys
import subprocess
import argparse
import requests
import tempfile
import os
import warnings
import time
import select
import termios
import tty
import datetime
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse

def process_url(url, args, ffuf_args, scanned_paths):
    url = url.strip().rstrip('/')
    url_with_fuzz = f"{url}/FUZZ"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_parts = domain.split('.')
    additional_keywords = set()
    for part in domain_parts:
        if part:
            part_lower = part.lower()
            additional_keywords.add(part_lower)
            # Add variations with extensions
            additional_keywords.add(f"{part_lower}.zip")
            additional_keywords.add(f"{part_lower}.tar.gz")
            additional_keywords.add(f"{part_lower}.7z")

    robots_url = f"{url}/robots.txt"
    disallowed_paths = []

    # Suppress warnings about unverified HTTPS requests
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    try:
        response = requests.get(robots_url, timeout=5, verify=False)
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if line.lower().startswith('disallow:'):
                    path = line[len('Disallow:'):].strip()
                    if path:
                        # Remove leading slash and any comments
                        path = path.split('#')[0].strip().lstrip('/')
                        if path:
                            disallowed_paths.append(path)
    except requests.RequestException:
        pass

    # Display the paths from robots.txt before scanning
    if disallowed_paths:
        print(f"The following paths were found in robots.txt for {url} and will be included in the scan:")
        for path in disallowed_paths:
            print(f"- {path}")
        print()

    # Display the additional keywords added from the domain
    if additional_keywords:
        print(f"The following keywords were extracted from the domain {domain} and will be included in the scan:")
        for keyword in additional_keywords:
            print(f"- {keyword}")
        print()

    # Combine the wordlist, disallowed paths, and additional keywords
    # Create a temporary wordlist file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_wordlist:
        # Write disallowed paths to the temporary wordlist
        for path in disallowed_paths:
            temp_wordlist.write(f"{path}\n")
            scanned_paths.add(path.strip())
        # Write additional keywords
        for keyword in additional_keywords:
            temp_wordlist.write(f"{keyword}\n")
            scanned_paths.add(keyword)
        # Append original wordlist content
        try:
            with open(args.wordlist, 'r') as original_wordlist:
                for line in original_wordlist:
                    line = line.strip()
                    temp_wordlist.write(f"{line}\n")
                    scanned_paths.add(line)
        except FileNotFoundError:
            sys.exit(1)
    temp_wordlist_path = temp_wordlist.name

    # Generate output filename
    date_str = datetime.datetime.now().strftime('%Y%m%d')
    safe_domain = domain.replace(':', '_')
    output_filename = f"{safe_domain}_{date_str}.json"

    # Small scan ffuf command without auto calibration
    ffuf_command = [
        'ffuf',
        '-w', temp_wordlist_path,
        '-u', url_with_fuzz,
        '-c',
        '-recursion',
        '-recursion-depth', '1',
        '-o', output_filename,
        '-of', 'json',
        '-or'
    ]

    # Append any additional ffuf arguments provided by the user
    ffuf_command.extend(ffuf_args)

    # Execute the ffuf command
    try:
        subprocess.run(ffuf_command)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 'interrupt'
    finally:
        # Clean up the temporary wordlist file
        os.remove(temp_wordlist_path)

    # Check if there are findings in the output file
    if os.path.exists(output_filename):
        print(f"Findings saved to {output_filename}")

    # Upon completion, ask the user if they want to continue with a larger list
    print("\nScan completed.")
    print("Do you want to continue with a larger list? Press any key to cancel (you have 5 seconds)...")
    # Wait for 5 seconds with countdown, check for any keypress
    # Save terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        start_time = time.time()
        while True:
            rlist, _, _ = select.select([sys.stdin], [], [], 1)
            if rlist:
                _ = sys.stdin.read(1)
                print("Cancelled.")
                return
            else:
                elapsed = int(time.time() - start_time)
                remaining = 5 - elapsed
                if remaining <= 0:
                    break
                print(f"{remaining}...", end='', flush=True)
                time.sleep(0.1)
                print('\r', end='', flush=True)
    finally:
        # Restore terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    # No keypress detected, proceed with the scan using the larger list
    print("\nNo keypress detected. Continuing with the larger list...")

    # Update the wordlist path to the larger list
    larger_wordlist = args.larger_wordlist

    # Create a new temporary wordlist file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_wordlist:
        # Write disallowed paths to the temporary wordlist
        for path in disallowed_paths:
            temp_wordlist.write(f"{path}\n")
        # Write additional keywords
        for keyword in additional_keywords:
            temp_wordlist.write(f"{keyword}\n")
        # Build set of paths from larger wordlist excluding scanned_paths
        try:
            with open(larger_wordlist, 'r') as original_wordlist:
                for line in original_wordlist:
                    line = line.strip()
                    if line not in scanned_paths:
                        temp_wordlist.write(f"{line}\n")
        except FileNotFoundError:
            print(f"Larger wordlist file not found: {larger_wordlist}")
            sys.exit(1)
    temp_wordlist_path = temp_wordlist.name

    # Generate new output filename for the larger scan
    date_str = datetime.datetime.now().strftime('%Y%m%d')
    safe_domain = domain.replace(':', '_')
    output_filename = f"{safe_domain}_{date_str}_larger.json"

    # Large scan ffuf command without additional extensions and with auto calibration
    ffuf_command = [
        'ffuf',
        '-w', temp_wordlist_path,
        '-u', url_with_fuzz,
        '-c',
        '-recursion',
        '-recursion-depth', '1',
        '-ac',  # Auto calibration
        '-o', output_filename,
        '-of', 'json',
        '-or'
    ]

    # Append any additional ffuf arguments provided by the user
    ffuf_command.extend(ffuf_args)

    # Execute the ffuf command
    try:
        subprocess.run(ffuf_command)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 'interrupt'
    finally:
        # Clean up the temporary wordlist file
        os.remove(temp_wordlist_path)

    # Check if there are findings in the output file
    if os.path.exists(output_filename):
        print(f"Findings saved to {output_filename}")

def main():
    parser = argparse.ArgumentParser(description='Wrapper script for ffuf.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='The base URL to fuzz.')
    group.add_argument('-l', '--list', help='File containing URLs to fuzz.')
    parser.add_argument('-w', '--wordlist', default='/root/tools/dirsearch/db/dicc.txt',
                        help='Path to the small wordlist (default: /root/tools/dirsearch/db/dicc.txt)')
    parser.add_argument('-W', '--larger-wordlist', default='/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt',
                        help='Path to the larger wordlist (default: /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt)')
    # Capture any additional arguments to pass to ffuf
    args, ffuf_args = parser.parse_known_args()

    scanned_paths = set()

    if args.url:
        result = process_url(args.url, args, ffuf_args, scanned_paths)
        if result == 'interrupt':
            sys.exit(0)
    elif args.list:
        try:
            with open(args.list, 'r') as url_file:
                urls = [line.strip() for line in url_file if line.strip()]
            # Check if URLs start with http:// or https://
            all_have_scheme = all(url.startswith('http://') or url.startswith('https://') for url in urls)
            if not all_have_scheme:
                # Use httpx to create a new file with properly formed URLs
                temp_urls_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                temp_urls_file.close()
                subprocess.run(['httpx', '-silent', '-l', args.list, '-o', temp_urls_file.name])
                with open(temp_urls_file.name, 'r') as url_file:
                    urls = [line.strip() for line in url_file if line.strip()]
                os.remove(temp_urls_file.name)
            for url in urls:
                result = process_url(url, args, ffuf_args, scanned_paths)
                if result == 'interrupt':
                    print("Do you want to continue with the next URL? (y/n): ", end='', flush=True)
                    choice = sys.stdin.readline().strip().lower()
                    if choice != 'y':
                        sys.exit(0)
                    else:
                        continue
        except FileNotFoundError:
            print(f"URL list file not found: {args.list}")
            sys.exit(1)

if __name__ == '__main__':
    main()
