import re
import requests
from bs4 import BeautifulSoup
import os
import json
from datetime import datetime, timedelta
import logging

logging.getLogger("neo4j").setLevel(logging.WARNING)

DEFAULT_HTTP_TIMEOUT_SECONDS = 30

def normalize_sid(sid_string):
    if not sid_string or not isinstance(sid_string, str):
        return sid_string

    if 'S-1-' in sid_string:
        sid_start = sid_string.find('S-1-')
        if sid_start > 0:
            return sid_string[sid_start:]
        else:
            return sid_string

    return sid_string

def parse_potfile_partitioned(potfile_path):
    cracked_passwords = {}
    ntlmv2_by_netbios = {}
    ntlmv2_pattern = re.compile(r'^([^:]+)::([^:]+):([^:]+):([^:]+):(.+)$')

    with open(potfile_path, "r", encoding='utf-8', errors='ignore') as file:
        line_count = 0
        for line in file:
            line_count += 1
            line = line.strip()
            if not line or line.count(':') < 1:
                continue

            try:
                hash_value, password = line.rsplit(":", 1)
                match = ntlmv2_pattern.match(hash_value)

                if match:
                    username = match.group(1).lower()
                    hash_domain = match.group(2).upper().split('.')[0]
                    ntlmv2_by_netbios.setdefault(hash_domain, {})[username] = password
                else:
                    cracked_passwords[hash_value.lower()] = password
            except ValueError as e:
                print(f"Error parsing line {line_count}: {e}")
                continue

    return cracked_passwords, ntlmv2_by_netbios


def load_ntds_hashes(ntds_file):
    ntds_user_hashes = {}
    lm_hashes = {} 
    blank_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
    default_lm_hash = "aad3b435b51404eeaad3b435b51404ee"
    no_lm_hash_indicator = "no lm-hash**********************"

    try:
        with open(ntds_file, "r", encoding='utf-8', errors='ignore') as file:
            line_count = 0
            processed_count = 0
            skipped_count = 0

            for line in file:
                line_count += 1
                line = line.strip()
                if not line:
                    continue

                parts = line.split(":")
                if len(parts) < 4:
                    skipped_count += 1
                    continue

                full_username = parts[0].lower()
                username = full_username.split('\\')[-1]
                nt_hash = parts[3].lower()

                if "no nt-hash" in nt_hash.lower() or nt_hash == "":
                    ntds_user_hashes[username] = blank_hash
                    processed_count += 1
                elif nt_hash and not nt_hash.lower().startswith("no"):
                    ntds_user_hashes[username] = nt_hash
                    processed_count += 1
                else:
                    skipped_count += 1

                if len(parts) >= 3:
                    lm_hash = parts[2].lower()
                    if lm_hash != default_lm_hash.lower() and lm_hash != no_lm_hash_indicator.lower():
                        lm_hashes[username] = lm_hash

    except FileNotFoundError:
        print(f"Error: NTDS file not found: {ntds_file}")
        return None, None
    except IOError as e:
        print(f"Error reading NTDS file: {e}")
        return None, None

    if not ntds_user_hashes:
        print("Warning: No valid NTDS hashes were loaded")

    return ntds_user_hashes, lm_hashes

def find_cracked_accounts(cracked_hashes, ntlmv2_hashes, ntds_data):
    cracked_accounts = {}
    blank_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
    
    if ntds_data is None:
        return cracked_accounts

    cracked_hashes = cracked_hashes or {}
    ntlmv2_hashes = ntlmv2_hashes or {}
    
    ntds_user_hashes, lm_hashes = ntds_data
    
    blank_passwords = 0
    ntlm_matches = 0
    ntlmv2_matches = 0
    
    for username, hash_value in ntds_user_hashes.items():
        username = username.lower()
        
        if hash_value == blank_hash:
            cracked_accounts[username] = ""
            blank_passwords += 1
        elif hash_value in cracked_hashes:
            cracked_accounts[username] = cracked_hashes[hash_value]
            ntlm_matches += 1
        elif username in ntlmv2_hashes:
            cracked_accounts[username] = ntlmv2_hashes[username]
            ntlmv2_matches += 1
            
    return cracked_accounts

def base_form(password):
    substitutions = {
        '@': 'a', '$': 's'
    }
    base_password = ''.join([substitutions.get(char, char) for char in password])
    base_password = re.sub(r'[^a-zA-Z0-9]', '', base_password)
    return base_password.lower()

def fetch_likely_usernames():
    base_url = "https://github.com/insidetrust/statistically-likely-usernames"
    raw_base_url = "https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/"
    print(f"Fetching username lists from {base_url}")
    
    likely_usernames = set()
    
    try:
        response = requests.get(base_url, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        txt_links = soup.find_all('a', href=lambda href: href and href.endswith('.txt'))
        print(f"Found {len(txt_links)} username files")
        
        for i, link in enumerate(txt_links, 1):
            file_path = link['href'].split('/')[-1]
            file_url = raw_base_url + file_path
            print(f"Processing file {i}/{len(txt_links)}: {file_path}")
            file_response = requests.get(file_url, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
            file_response.raise_for_status()
            file_content = file_response.text
            usernames = set(username.strip().lower() for username in file_content.split('\n') if username.strip())
            likely_usernames.update(usernames)
            print(f"  Added {len(usernames)} usernames from {file_path}")
        
        print(f"Total unique usernames collected: {len(likely_usernames)}")
    
    except requests.RequestException as e:
        print(f"Error fetching usernames from GitHub: {e}")
    
    return likely_usernames

def analyse_usernames(cracked_usernames, likely_usernames):
    matched_usernames = set(cracked_usernames) & likely_usernames
    return list(matched_usernames)

def fetch_and_store_usernames(force_update=False):
    filename = "likely_usernames.json"
    current_time = datetime.now()

    if os.path.exists(filename) and not force_update:
        with open(filename, 'r') as f:
            data = json.load(f)
        last_updated = datetime.fromisoformat(data['last_updated'])
        if current_time - last_updated < timedelta(days=30):
            print("Using cached username data")
            return set(data['usernames'])

    print("Fetching new username data from GitHub")
    usernames = fetch_likely_usernames()

    data = {
        'last_updated': current_time.isoformat(),
        'usernames': list(usernames)
    }
    with open(filename, 'w') as f:
        json.dump(data, f)

    return usernames

def get_likely_usernames():
    return fetch_and_store_usernames()

def load_ntds_hashes_with_metadata(ntds_file):
    # Returns [{domain_prefix, username, rid, nt_hash, lm_hash}, ...]
    entries = []
    blank_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
    default_lm_hash = "aad3b435b51404eeaad3b435b51404ee"
    no_lm_hash_indicator = "no lm-hash**********************"

    try:
        with open(ntds_file, "r", encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(":")
                if len(parts) < 4:
                    continue

                full_username = parts[0]
                domain_prefix = None
                if '\\' in full_username:
                    domain_prefix, username = full_username.split('\\', 1)
                    domain_prefix = domain_prefix.strip()
                else:
                    username = full_username

                username = username.strip().lower()
                rid = parts[1].strip() if len(parts) > 1 else None
                lm_hash_raw = parts[2].lower().strip() if len(parts) > 2 else None
                nt_hash = parts[3].lower().strip()

                if "no nt-hash" in nt_hash.lower() or nt_hash == "":
                    nt_hash = blank_hash
                elif nt_hash.lower().startswith("no"):
                    continue

                lm_hash = None
                if lm_hash_raw and lm_hash_raw != default_lm_hash.lower() and lm_hash_raw != no_lm_hash_indicator.lower():
                    lm_hash = lm_hash_raw

                entries.append({
                    'domain_prefix': domain_prefix,
                    'username': username,
                    'rid': rid,
                    'nt_hash': nt_hash,
                    'lm_hash': lm_hash,
                })
    except FileNotFoundError:
        print(f"Error: NTDS file not found: {ntds_file}")
        return []
    except IOError as e:
        print(f"Error reading NTDS file: {e}")
        return []

    return entries

def partition_ntds_by_domain(ntds_entries, rid_map, prefix_map, all_domains):
    # Built-in RIDs (500, 501, 502) without a domain prefix get assigned to ALL domains
    BUILTIN_RIDS = {'500', '501', '502'}

    domain_by_prefix = {}
    domain_by_fqdn = {}
    for d in all_domains:
        pfx = d.upper().split('.')[0].lower()
        domain_by_prefix[pfx] = d
        domain_by_fqdn[d.lower()] = d

    domain_hashes = {}
    for d in all_domains:
        domain_hashes[d] = ({}, {})

    for entry in ntds_entries:
        username = entry['username']
        rid = entry['rid']
        nt_hash = entry['nt_hash']
        lm_hash = entry['lm_hash']
        domain_prefix = entry['domain_prefix']

        assigned_domains = []

        if domain_prefix:
            pfx_lower = domain_prefix.lower()
            key = (pfx_lower, username)
            if key in prefix_map:
                assigned_domains.append(prefix_map[key])
            elif pfx_lower in domain_by_fqdn:
                assigned_domains.append(domain_by_fqdn[pfx_lower])
            elif pfx_lower in domain_by_prefix:
                assigned_domains.append(domain_by_prefix[pfx_lower])
            else:
                short_pfx = pfx_lower.split('.')[0]
                if short_pfx in domain_by_prefix:
                    assigned_domains.append(domain_by_prefix[short_pfx])
        else:
            if rid:
                key = (username, rid)
                if key in rid_map:
                    domains_for_key = rid_map[key]
                    if len(domains_for_key) == 1:
                        assigned_domains = list(domains_for_key)
                    elif rid in BUILTIN_RIDS:
                        assigned_domains = list(all_domains)

                if not assigned_domains and rid in BUILTIN_RIDS:
                    assigned_domains = list(all_domains)

        if not assigned_domains:
            continue

        for domain in assigned_domains:
            if domain not in domain_hashes:
                domain_hashes[domain] = ({}, {})
            user_hashes, lm_dict = domain_hashes[domain]
            user_hashes[username] = nt_hash
            if lm_hash:
                lm_dict[username] = lm_hash

    return domain_hashes
