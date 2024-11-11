#!/usr/bin/env python3
import sys
import subprocess
import argparse
import requests
import tempfile
import os
import warnings
import datetime
import random
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse

def process_url(url, args, ffuf_args, add_se=False):
    url = url.strip().rstrip('/')
    url_with_fuzz = f"{url}/FUZZ"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path  # Adjusted to handle URLs without scheme
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

    robots_url = f"{url.rstrip('/')}/robots.txt"
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
                            disallowed_paths.append(path.lower())  # Convert to lowercase
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

    # Additional priority words provided by the user, without leading '/'
    user_priority_words = [
        'wp-backup.sh',
        'submit.sh',
        'stage-deploy.sh',
        'scripts/driverenv.sh',
        's3.sh',
        'run-deploy.sh',
        'passwords.sh',
        'm/index.php',
        'library.sh',
        'installer.sh',
        'envvars.sh',
        'driverenv.sh',
        'driver.sh',
        'docker/startup.sh',
        'develop.sh',
        'bucket.sh',
        'aws_cli.sh',
        'aws-env.sh',
        'swagger.json',
        'swagger.yaml',
        'swagger-ui',
        'api-docs',
        'v2/api-docs',
        'v3/api-docs',
        'api',
        'services',
        'swagger',
        'swagger/v1/swagger.json'
    ]

    # Remove leading slashes and convert to lowercase
    user_priority_words = [word.lstrip('/').lower() for word in user_priority_words]

    # Get the list of extensions specified in ffuf command
    extensions = ['.php', '.aspx', '.jsp', '.html', '.js', '.json']

    # Build the combined wordlist according to the specified order
    combined_wordlist = []

    scanned_paths = set()  # Initialize scanned_paths here to track duplicates within this URL

    # First, add disallowed paths and additional keywords
    for path in disallowed_paths:
        path = path.strip().lower()
        if path not in scanned_paths:
            combined_wordlist.append(path)
            scanned_paths.add(path)
    for keyword in additional_keywords:
        keyword = keyword.strip().lower()
        if keyword not in scanned_paths:
            combined_wordlist.append(keyword)
            scanned_paths.add(keyword)

    # Add user-provided priority words
    for word in user_priority_words:
        word = word.strip().lower()
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)

    # Add words from the user-provided priority wordlist
    if args.priority_wordlist:
        try:
            with open(args.priority_wordlist, 'r') as priority_wordlist_file:
                for line in priority_wordlist_file:
                    word = line.strip().lower()
                    if word and word not in scanned_paths:
                        combined_wordlist.append(word)
                        scanned_paths.add(word)
        except FileNotFoundError:
            print(f"Priority wordlist file not found: {args.priority_wordlist}")
            sys.exit(1)

    # Read the original wordlist and categorize the entries
    words_starting_with_config = []
    words_env = []
    other_words = []
    try:
        with open(args.wordlist, 'r') as original_wordlist:
            for line in original_wordlist:
                word = line.strip().lower()
                if word:
                    # Remove words that have extensions matching the specified ones
                    if any(word.endswith(ext) for ext in extensions):
                        continue
                    if word.startswith('config'):
                        words_starting_with_config.append(word)
                    elif word in ['env', '.env']:
                        words_env.append(word)
                    else:
                        other_words.append(word)
    except FileNotFoundError:
        sys.exit(1)

    # Remove duplicates while preserving order
    words_starting_with_config = list(dict.fromkeys(words_starting_with_config))
    words_env = list(dict.fromkeys(words_env))
    other_words = list(dict.fromkeys(other_words))

    # Randomize the order of the other words
    random.shuffle(other_words)

    # Combine all words in the specified order
    for word in words_starting_with_config:
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)
    for word in words_env:
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)
    for word in other_words:
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)

    # Create a temporary wordlist file and write the combined wordlist
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_wordlist:
        for word in combined_wordlist:
            temp_wordlist.write(f"{word}\n")
    temp_wordlist_path = temp_wordlist.name

    # Generate output filename
    date_str = datetime.datetime.now().strftime('%Y%m%d')
    safe_domain = domain.replace(':', '_').replace('/', '_')
    output_filename = f"{safe_domain}_{date_str}.json"

    # Short scan ffuf command with specified extensions
    ffuf_command = [
        'ffuf',
        '-w', temp_wordlist_path,
        '-u', url_with_fuzz,
        '-c',
        '-recursion',
        '-recursion-depth', '1',
        '-e', ','.join(extensions),  # Use the extensions list
    ]

    # If add_se is True, add '-se' to ffuf_command
    if add_se:
        ffuf_command.append('-se')

    # Continue building ffuf_command
    ffuf_command.extend([
        '-o', output_filename,
        '-of', 'json',
        '-or'
    ])

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

    # If the --long-test flag is not set, skip the longer scan
    if not args.long_test:
        print("Skipping longer scan. Use --long-test to perform both scans.")
        return

    # Proceed to longer scan
    print("\nStarting longer scan with larger wordlist...")

    # Larger scan
    larger_wordlist = args.larger_wordlist

    # Build the combined wordlist for the longer scan
    combined_wordlist = []

    scanned_paths = set()  # Reset scanned_paths for the longer scan

    # First, add disallowed paths and additional keywords
    for path in disallowed_paths:
        path = path.strip().lower()
        if path not in scanned_paths:
            combined_wordlist.append(path)
            scanned_paths.add(path)
    for keyword in additional_keywords:
        keyword = keyword.strip().lower()
        if keyword not in scanned_paths:
            combined_wordlist.append(keyword)
            scanned_paths.add(keyword)

    # Add user-provided priority words
    for word in user_priority_words:
        word = word.strip().lower()
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)

    # Add words from the user-provided priority wordlist
    if args.priority_wordlist:
        try:
            with open(args.priority_wordlist, 'r') as priority_wordlist_file:
                for line in priority_wordlist_file:
                    word = line.strip().lower()
                    if word and word not in scanned_paths:
                        combined_wordlist.append(word)
                        scanned_paths.add(word)
        except FileNotFoundError:
            print(f"Priority wordlist file not found: {args.priority_wordlist}")
            sys.exit(1)

    # Read the larger wordlist and categorize the entries
    words_starting_with_config = []
    words_env = []
    other_words = []
    try:
        with open(larger_wordlist, 'r') as original_wordlist:
            for line in original_wordlist:
                word = line.strip().lower()
                if word:
                    # Remove words that have extensions matching the specified ones
                    if any(word.endswith(ext) for ext in extensions):
                        continue
                    if word.startswith('config'):
                        words_starting_with_config.append(word)
                    elif word in ['env', '.env']:
                        words_env.append(word)
                    else:
                        other_words.append(word)
    except FileNotFoundError:
        print(f"Larger wordlist file not found: {larger_wordlist}")
        sys.exit(1)

    # Remove duplicates while preserving order
    words_starting_with_config = list(dict.fromkeys(words_starting_with_config))
    words_env = list(dict.fromkeys(words_env))
    other_words = list(dict.fromkeys(other_words))

    # Randomize the order of the other words
    random.shuffle(other_words)

    # Combine all words in the specified order
    for word in words_starting_with_config:
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)
    for word in words_env:
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)
    for word in other_words:
        if word not in scanned_paths:
            combined_wordlist.append(word)
            scanned_paths.add(word)

    # Create a temporary wordlist file and write the combined wordlist
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_wordlist:
        for word in combined_wordlist:
            temp_wordlist.write(f"{word}\n")
    temp_wordlist_path = temp_wordlist.name

    # Generate new output filename for the longer scan
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
        print("\nLonger scan interrupted.")
        return 'interrupt'
    finally:
        os.remove(temp_wordlist_path)

    if os.path.exists(output_filename):
        print(f"Longer scan findings saved to {output_filename}")

def main():
    parser = argparse.ArgumentParser(description='Wrapper script for ffuf.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='The base URL to fuzz.')
    group.add_argument('-l', '--list', help='File containing URLs to fuzz.')
    parser.add_argument('-w', '--wordlist', default='/root/tools/dirsearch/db/dicc.txt',
                        help='Path to the small wordlist (default: /root/tools/dirsearch/db/dicc.txt)')
    parser.add_argument('-W', '--larger-wordlist', default='/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt',
                        help='Path to the larger wordlist (default: /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt)')
    parser.add_argument('--priority-wordlist', help='Path to a small priority wordlist to be used before the normal wordlist')
    parser.add_argument('--long-test', action='store_true', help='Perform both the short and longer scans')
    # Capture any additional arguments to pass to ffuf
    args, ffuf_args = parser.parse_known_args()

    if args.url:
        url = args.url.strip()
        # Check if URL starts with http:// or https://
        if not (url.startswith('http://') or url.startswith('https://')):
            # Use httpx to test both HTTP and HTTPS
            print(f"Testing both HTTP and HTTPS for {url} using httpx...")
            temp_url_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
            temp_url_file.write(url + '\n')
            temp_url_file.close()
            temp_output_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
            temp_output_file.close()
            subprocess.run(['httpx', '-silent', '-l', temp_url_file.name, '-o', temp_output_file.name])
            with open(temp_output_file.name, 'r') as output_file:
                urls = [line.strip() for line in output_file if line.strip()]
            os.remove(temp_url_file.name)
            os.remove(temp_output_file.name)
            if urls:
                # Prefer HTTPS if available
                https_urls = [u for u in urls if u.startswith('https://')]
                if https_urls:
                    url = https_urls[0]
                else:
                    url = urls[0]
            else:
                print(f"Could not resolve {url} with HTTP or HTTPS.")
                sys.exit(1)
        result = process_url(url, args, ffuf_args, add_se=False)
        if result == 'interrupt':
            sys.exit(0)
    elif args.list:
        try:
            with open(args.list, 'r') as url_file:
                urls = [line.strip() for line in url_file if line.strip()]
            # Randomize the order of URLs before processing
            random.shuffle(urls)
            # Check if URLs start with http:// or https://
            all_have_scheme = all(url.startswith('http://') or url.startswith('https://') for url in urls)
            if not all_have_scheme:
                # Use httpx to resolve URLs and detect technologies
                print("Using httpx to resolve URLs without scheme and detect technologies...")
                temp_urls_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                temp_urls_file.close()
                # Write randomized URLs to a temporary file
                with open(temp_urls_file.name, 'w') as temp_file:
                    for url in urls:
                        temp_file.write(f"{url}\n")
                # Run httpx with -td to detect technologies
                subprocess.run(['httpx', '-td', '-silent', '-l', temp_urls_file.name, '-o', temp_urls_file.name + '_output'])
                # Parse the httpx output and categorize URLs
                priority_urls = []
                other_urls = []
                unprocessed_urls = []
                with open(temp_urls_file.name + '_output', 'r') as url_file:
                    for line in url_file:
                        line = line.strip()
                        if not line:
                            continue
                        # Expected format: URL [Title] [Technologies]
                        parts = line.split('[')
                        url_part = parts[0].strip()
                        technologies = ''
                        if len(parts) > 2:
                            technologies = '[' + '['.join(parts[2:])  # Reconstruct technologies part
                        elif len(parts) > 1:
                            technologies = '[' + parts[1]  # Include the '[' back
                        technologies = technologies.replace(']', '').strip()
                        technologies_lower = technologies.lower()
                        # Check for exclusion technologies
                        exclusion_techs = ['vpn', 'checkpoint', 'imperva', 'cloudflare', 'cisco']
                        if any(tech in technologies_lower for tech in exclusion_techs):
                            unprocessed_urls.append(url_part)
                            continue
                        # Check for priority technologies
                        priority_techs = ['php', 'tomcat', 'iis:8.5']
                        if any(tech in technologies_lower for tech in priority_techs):
                            priority_urls.append(url_part)
                        else:
                            other_urls.append(url_part)
                os.remove(temp_urls_file.name)
                os.remove(temp_urls_file.name + '_output')
                # Write the categorized URLs to files
                if unprocessed_urls:
                    with open('unprocessed.txt', 'w') as f:
                        for url in unprocessed_urls:
                            f.write(f"{url}\n")
                    print(f"Excluded URLs saved to unprocessed.txt")
                # Combine priority and other URLs
                urls = priority_urls + other_urls
            # Determine if -se should be added (more than 5 URLs)
            add_se = len(urls) > 5
            for url in urls:
                result = process_url(url, args, ffuf_args, add_se)
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
