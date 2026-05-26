from __future__ import annotations

import os
from typing import Callable

from .BloodhoundImporter import BloodhoundImporter
from .config_loader import DEFAULT_EXCLUDED_RELATIONSHIPS, load as load_resolved_config
from .neo4j_connection import Neo4jConnection


def ensure_exclusions_section(config) -> None:
    if not config.has_section('EXCLUSIONS'):
        config.add_section('EXCLUSIONS')
    if not config.has_option('EXCLUSIONS', 'excluded_relationships'):
        config.set(
            'EXCLUSIONS',
            'excluded_relationships',
            ',\n    '.join(DEFAULT_EXCLUDED_RELATIONSHIPS),
        )


def save_config(config, config_file) -> None:
    is_new = not os.path.exists(config_file)
    ensure_exclusions_section(config)
    with open(config_file, 'w') as configfile:
        config.write(configfile)
    if is_new:
        try:
            os.chmod(config_file, 0o600)
        except OSError:
            pass


def disable_bloodhound(config, config_file, base_url) -> None:
    if not config.has_section('BLOODHOUND'):
        config.add_section('BLOODHOUND')
    config['BLOODHOUND']['url'] = base_url
    config['BLOODHOUND']['enabled'] = 'False'
    save_config(config, config_file)


def get_valid_neo4j_credentials(
    resolved,
    config,
    config_file,
    *,
    input_fn: Callable[[str], str] = input,
    neo4j_factory: Callable[..., Neo4jConnection] = Neo4jConnection,
) -> tuple[str, str]:
    default_user = "neo4j"
    default_pwd = "bloodhoundcommunityedition"
    uri = resolved.neo4j_uri
    user = pwd = None

    print("Attempting to connect with default credentials...")
    try:
        temp_conn = neo4j_factory(uri, default_user, default_pwd)
        if temp_conn.is_connected():
            print("Successfully connected to Neo4j server using default credentials.")
            temp_conn.close()
            user, pwd = default_user, default_pwd
    except Exception as e:
        print(f"Default credentials failed: {e}")
        print("Please enter your Neo4j credentials:")

    while user is None:
        candidate_user = input_fn("Enter the Neo4j username: ")
        candidate_pwd = input_fn("Enter the Neo4j password: ")
        try:
            temp_conn = neo4j_factory(uri, candidate_user, candidate_pwd)
            if temp_conn.is_connected():
                print("Successfully connected to Neo4j server.")
                temp_conn.close()
                user, pwd = candidate_user, candidate_pwd
            else:
                print("Unable to connect to Neo4j server with the provided credentials. Please try again.\n")
        except Exception as e:
            print(f"Connection failed: {e}\nPlease try again.\n")

    if not config.has_section('NEO4J'):
        config.add_section('NEO4J')
    config['NEO4J'] = {'uri': uri, 'username': user, 'password': pwd}

    if not config.has_section('BLOODHOUND'):
        config.add_section('BLOODHOUND')
    config['BLOODHOUND'].setdefault('url', 'http://localhost:8080')
    config['BLOODHOUND'].setdefault('username', 'admin')
    config['BLOODHOUND'].setdefault('enabled', 'True')
    save_config(config, config_file)
    print("Neo4j and BloodHound configuration saved.")
    assert pwd is not None
    return user, pwd


def get_valid_bloodhound_credentials(
    resolved,
    config,
    config_file,
    *,
    force: bool = False,
    input_fn: Callable[[str], str] = input,
    bh_factory: Callable[..., BloodhoundImporter] = BloodhoundImporter,
):
    max_attempts = 3
    attempts = 0
    base_url = resolved.bh_url

    if not force and not resolved.bh_enabled:
        return None, None

    if resolved.bh_username and resolved.bh_password:
        username = resolved.bh_username
        password = resolved.bh_password.expose()
        importer = bh_factory(None, bloodhound_username=username, bloodhound_password=password, base_url=base_url)
        try:
            importer._authenticate()
            print("Successfully authenticated with BloodHound API using stored credentials.")
            if force:
                if not config.has_section('BLOODHOUND'):
                    config.add_section('BLOODHOUND')
                config['BLOODHOUND']['enabled'] = 'True'
                save_config(config, config_file)
            return username, password
        except Exception as e:
            print(f"Stored BloodHound credentials failed: {e}")
    elif resolved.bh_username or resolved.bh_password:
        print("BloodHound credentials are missing in the configuration.")

    while attempts < max_attempts:
        username = input_fn("If using BloodHound CE, provide BloodHound username (or press Enter to skip): ").strip()
        if not username:
            print("Skipping BloodHound integration as per user choice.")
            disable_bloodhound(config, config_file, base_url)
            return None, None

        password = input_fn("If using BloodHound CE, provide BloodHound password (or press Enter to skip): ").strip()
        if not password:
            print("Skipping BloodHound integration as per user choice.")
            disable_bloodhound(config, config_file, base_url)
            return None, None

        importer = bh_factory(None, bloodhound_username=username, bloodhound_password=password, base_url=base_url)

        try:
            importer._authenticate()
            if not config.has_section('BLOODHOUND'):
                config.add_section('BLOODHOUND')
            config['BLOODHOUND']['url'] = base_url
            config['BLOODHOUND']['username'] = username
            config['BLOODHOUND']['password'] = password
            config['BLOODHOUND']['enabled'] = 'True'
            save_config(config, config_file)
            print("BloodHound credentials saved to configuration.")
            return username, password
        except Exception as e:
            attempts += 1
            print(f"Authentication failed: {e}")
            if attempts < max_attempts:
                print(f"Please try again ({max_attempts - attempts} attempts left).\n")
            else:
                print("Maximum attempts reached. Skipping BloodHound integration.\n")
                disable_bloodhound(config, config_file, base_url)
    return None, None


def connect_neo4j_and_load_bloodhound(
    resolved,
    config,
    config_file,
    *,
    input_fn: Callable[[str], str] = input,
    neo4j_factory: Callable[..., Neo4jConnection] = Neo4jConnection,
):
    uri = resolved.neo4j_uri
    bootstrap_fired = False

    if resolved.neo4j_username and resolved.neo4j_password:
        try:
            conn = neo4j_factory(uri, resolved.neo4j_username, resolved.neo4j_password.expose())
            if not conn.is_connected():
                print("Stored Neo4j credentials are invalid. Trying default credentials...")
                user, pwd = get_valid_neo4j_credentials(
                    resolved, config, config_file,
                    input_fn=input_fn, neo4j_factory=neo4j_factory,
                )
                conn = neo4j_factory(uri, user, pwd)
                bootstrap_fired = True
        except Exception as e:
            print(f"Failed to connect with stored credentials: {e}")
            print("Trying default credentials...")
            user, pwd = get_valid_neo4j_credentials(
                resolved, config, config_file,
                input_fn=input_fn, neo4j_factory=neo4j_factory,
            )
            conn = neo4j_factory(uri, user, pwd)
            bootstrap_fired = True
    elif not os.path.exists(config_file):
        print("Configuration file not found. Trying default Neo4j credentials...")
        user, pwd = get_valid_neo4j_credentials(
            resolved, config, config_file,
            input_fn=input_fn, neo4j_factory=neo4j_factory,
        )
        conn = neo4j_factory(uri, user, pwd)
        bootstrap_fired = True
    else:
        print("Neo4j credentials not found in the config file.")
        user, pwd = get_valid_neo4j_credentials(
            resolved, config, config_file,
            input_fn=input_fn, neo4j_factory=neo4j_factory,
        )
        conn = neo4j_factory(uri, user, pwd)
        bootstrap_fired = True

    # Re-apply env overlay over the bootstrap-written [BLOODHOUND] defaults.
    if bootstrap_fired:
        resolved = load_resolved_config(config_file)

    bh_username = resolved.bh_username
    bh_password = resolved.bh_password.expose() if resolved.bh_password else None
    bh_enabled = resolved.bh_enabled

    return conn, bh_username, bh_password, bh_enabled
