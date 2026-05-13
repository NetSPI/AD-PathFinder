class UserQuery:
    def __init__(self, neo4j_data, cracked_accounts=None, ntds_hashes=None):
        self.neo4j_data = neo4j_data
        self.cracked_accounts = cracked_accounts or {}
        self.ntds_hashes = ntds_hashes

    def check_user(self):
        cracked_accounts = self.cracked_accounts
        user_escalation_paths = {}

        while True:
            username_input = input("Enter username, computers require FQDN, computer01.training.local (type 'back' to return): ").strip().lower()

            if not username_input:
                print("\nWarning: Input cannot be empty. Please enter a valid username/computer or 'back'")
                continue

            if username_input != 'back' and '.' not in username_input and len(username_input) < 2:
                print("\nWarning: Please enter a valid username, computer FQDN, or 'back'")
                continue
            print()
            if username_input == "back":
                break

            print(f"Searching for user: {username_input}")

            user_results = self.neo4j_data.get_all_users_with_attributes(username=username_input)

            if user_results and len(user_results) > 0:
                user_data = user_results[0]
                self.display_user_info(username_input, user_data, cracked_accounts)

                if not user_data.get('isAdmin', False):
                    username_with_domain = (user_data.get('username_with_domain') or '').upper()
                    if not username_with_domain:
                        continue
                    escalation_path_info = self.neo4j_data.get_user_escalation_paths_all_paths(
                        username_with_domain,
                        force_refresh=True
                    )

                    has_escalation_path = any(res.get('hasEscalationPath', False) for res in escalation_path_info) if escalation_path_info else False

                    if has_escalation_path:
                        all_paths = [res.get('fullPath', []) for res in escalation_path_info if res.get('hasEscalationPath')]
                        user_escalation_paths[username_input] = all_paths
                        self.display_escalation_paths(username_input, {username_input: all_paths})
                    else:
                        print(f"\nNo escalation paths found for user '{username_input}'")
                else:
                    print(f"\nUser '{username_input}' is an admin - skipping escalation path check")
            else:
                print(f"User '{username_input}' not found.")

    def display_user_info(self, username, user_info, cracked_accounts):
        ntds_user_hashes = None
        if self.ntds_hashes:
            ntds_user_hashes, _ = self.ntds_hashes

        user_hash = ntds_user_hashes.get(username) if ntds_user_hashes else None

        is_enabled = user_info['enabled']
        is_admin = user_info.get('isAdmin', False)
        is_computer_account = username.endswith('$')
        description = user_info.get('description', "No description available")

        password_status = f"Password cracked: {cracked_accounts[username]}" if username in cracked_accounts else "Password status: Not found in potfile"
        enabled_status = "Enabled" if is_enabled else "Disabled"
        admin_status = "Admin Status: Yes" if is_admin else ""
        computer_status = "Computer Account" if is_computer_account else ""

        output_lines = [
            f"\n{username}\n{'NTLM hash: ' + user_hash if user_hash else 'NTLM hash not found'}",
            password_status,
            f"Status: {enabled_status}",
        ]

        if is_admin:
            output_lines.append(admin_status)
        if is_computer_account:
            output_lines.append(computer_status)
        output_lines.append(f"Description: {description}")

        print("\n".join(output_lines))

        groups = user_info.get('groups', [])
        if groups:
            print("\nGroups:")
            for group in groups:
                print(f" - {group}")
        else:
            print("\nNo groups found.")
    
    def display_escalation_paths(self, username, user_escalation_paths):
        print(f"\nUser '{username}' has an escalation path.")
    
        path_groups = {}
    
        for path in user_escalation_paths.get(username, []):
            if not path:
                continue
    
            formatted_parts = []
            has_contains = False
    
            for i in range(0, len(path), 2):
                node_name = None
                if i < len(path):
                    if isinstance(path[i], dict) and path[i].get('name'):
                        node_name = path[i]['name'].lower()
                    else:
                        node_name = str(path[i]).lower()
                        
                    formatted_parts.append(node_name)

                if i+1 < len(path):
                    rel = str(path[i+1]).lower()
                    if rel == 'contains':
                        has_contains = True
                        break
                    formatted_parts.append(rel)
    
            if has_contains:
                continue
    
            path_string = " -> ".join(formatted_parts)
    
            prefix_length = min(7, len(formatted_parts))
            path_prefix = tuple(formatted_parts[:prefix_length])
    
            if path_prefix not in path_groups:
                path_groups[path_prefix] = []
            path_groups[path_prefix].append((path_string, len(formatted_parts)))
    
        final_paths = set()
        for paths in path_groups.values():
            shortest_path = min(paths, key=lambda x: x[1])[0]
            final_paths.add(shortest_path)
    
        if final_paths:
            print(f"\nFound {len(final_paths)} escalation paths:")
            for i, path in enumerate(sorted(final_paths), 1):
                print(f"{i}. {path}")
        else:
            print("No valid paths found.")
    
        print("\n")