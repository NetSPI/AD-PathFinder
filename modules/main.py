import configparser
import argparse
import os
import sys
import time
import argcomplete
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from .neo4j_data import Neo4jData
from .account_analysis import AccountAnalysis
from .analysis import Analysis
from .reporting import Reporting
from .user_query import UserQuery
from .utils import load_ntds_hashes
from .audit_context import MultiDomainAuditContext
from .BloodhoundImporter import BloodhoundImporter
from .client_report_generator import ClientReportGenerator
from .config_loader import load as load_resolved_config
from .config_manager import (
    connect_neo4j_and_load_bloodhound,
    get_valid_bloodhound_credentials,
    get_valid_neo4j_credentials,
    save_config,
)

path_completer = PathCompleter()


def run_client_report_generation(report_dir, domain_name):
    import json as _json
    from contextlib import redirect_stdout, redirect_stderr

    ad_json = os.path.join(report_dir, f"{domain_name.lower()}_domain_audit.json")
    if not os.path.isfile(ad_json):
        return

    try:
        with open(ad_json, 'r', encoding='utf-8-sig') as f:
            ad_data = _json.load(f)
    except Exception as e:
        print(f"Warning: Failed to read {ad_json}: {e}")
        return

    with open(os.devnull, 'w') as _quiet:
        try:
            with redirect_stdout(_quiet), redirect_stderr(_quiet):
                html_path = os.path.join(report_dir, f"{domain_name.lower()}_AD_report.html")
                ClientReportGenerator(json_data=ad_data).generate(html_path)
            print(f"[+] Generated: {os.path.basename(html_path)}")
        except Exception as e:
            print(f"Warning: AD report generation failed: {e}")


def _record_final_inventory(report_dir, domain_name, diagnostics):
    if not os.path.isdir(report_dir):
        return
    for stale in ("platform_ad_audit.json", "platform_password_audit.json"):
        stale_path = os.path.join(report_dir, stale)
        if os.path.isfile(stale_path):
            try:
                os.remove(stale_path)
            except OSError:
                pass
    if not diagnostics:
        return
    report_files = {}
    for fname in sorted(os.listdir(report_dir)):
        fpath = os.path.join(report_dir, fname)
        if os.path.isfile(fpath):
            report_files[fname] = os.path.getsize(fpath)
    diagnostics.report_generation[domain_name] = report_files


def populate_neo4j_passwords(conn, neo4j_data, account_analysis, ntds_file_path, config, bloodhound_username=None, bloodhound_password=None, *, bloodhound_url):
    # Skip if >85% of cracked accounts already have passwords in Neo4j
    if not hasattr(account_analysis, 'cracked_accounts') or not account_analysis.cracked_accounts:
        return False

    cracked_accounts_count = len(account_analysis.cracked_accounts)
    if cracked_accounts_count == 0:
        return False

    print("Checking existing password data in Neo4j...")

    total_users, users_with_passwords, users_marked_owned = neo4j_data.check_passwords_populated(account_analysis)

    if total_users == 0:
        return False

    update_percentage = min(users_with_passwords, users_marked_owned) / cracked_accounts_count * 100

    if update_percentage >= 85:
        return False

    accounts_to_update = cracked_accounts_count - min(users_with_passwords, users_marked_owned)
    print(f"[*] Populating Neo4j with {accounts_to_update} clear-text passwords and marking accounts as owned...")

    if not bloodhound_username or not bloodhound_password:
        if config and config.has_section('BLOODHOUND'):
            bloodhound_username = config.get('BLOODHOUND', 'username', fallback=None)
            bloodhound_password = config.get('BLOODHOUND', 'password', fallback=None)
            bloodhound_enabled = config.getboolean('BLOODHOUND', 'enabled', fallback=False)

            if not bloodhound_enabled or not bloodhound_username or not bloodhound_password:
                return False

    importer = BloodhoundImporter(conn, bloodhound_username=bloodhound_username, bloodhound_password=bloodhound_password, base_url=bloodhound_url)
    importer.neo4j_data = neo4j_data
    importer.cracked_accounts = account_analysis.cracked_accounts

    cracked_users_list = list(account_analysis.cracked_accounts.keys())

    try:
        importer.mark_as_owned(cracked_users_list, ntds_file_path)
        return True
    except Exception:
        return False

def check_database_has_data(neo4j_conn):
    neo4j_data = Neo4jData(neo4j_conn)
    domain_name = neo4j_data.get_domain_name()
    return domain_name != "Unknown Domain"

def _is_mssql_import(zip_path):
    import zipfile
    import json
    from pathlib import Path
    from modules.BloodhoundImporter import is_mssql_data

    try:
        with zipfile.ZipFile(Path(zip_path), 'r') as zf:
            json_files = [f for f in zf.namelist() if f.endswith('.json')]

            for json_file in json_files[:3]:
                try:
                    with zf.open(json_file) as f:
                        if is_mssql_data(json.load(f)):
                            return True
                except Exception:
                    continue
        return False
    except Exception:
        return False

def handle_import_with_check(args, importer, conn):
    import_files = args.import_file if isinstance(args.import_file, list) else [args.import_file]
    is_mssql_import = any(_is_mssql_import(f) for f in import_files)

    if check_database_has_data(conn):
        if is_mssql_import:
            print(f"[INFO] Importing MSSQL data")
            print("[INFO] MSSQL data will be added to existing BloodHound data")
        else:
            print("\nWARNING: BloodHound data already exists in the database!")
            print(f"Current domain: {Neo4jData(conn).get_domain_name()}")
            print("\nImporting new data will ADD to the existing data, not replace it.")
            print("If you want to replace the data, please delete it first using the -d flag.")

            confirmation = input("\nDo you want to continue with the import? (yes/no): ").strip().lower()
            if confirmation not in ['yes', 'y']:
                print("Import aborted by user.")
                return False

    data_type = "MSSQL data" if is_mssql_import else "BloodHound data"
    file_count = len(import_files)
    print(f"Importing {data_type} from {file_count} file(s)")

    if importer.import_zip(args.import_file):
        print(f"Successfully imported {data_type}")
        return True
    else:
        print(f"Failed to import {data_type}")
        return False

def _record_diagnostics_domains(diagnostics, domains):
    if not diagnostics:
        return
    seen = set(diagnostics.domains)
    for domain in domains:
        if domain and domain not in seen:
            diagnostics.domains.append(domain)
            seen.add(domain)


def _run_single_domain_audit(reporting, company_names, audit_label, generate_reports,
                             diagnostics=None,
                             start_message=None, completion_message=None):
    domain_name = reporting.neo4j_data.get_domain_name()
    report_dir = f"report_{domain_name.lower()}"
    if start_message:
        print(f"\n{start_message.format(report_dir=report_dir, domain_name=domain_name)}")
    else:
        print(f"\nGenerating {audit_label} reports in directory: {report_dir}")

    generate_reports(reporting, company_names, {})
    if completion_message:
        print(f"\n{completion_message.format(report_dir=report_dir, domain_name=domain_name)}")
    run_client_report_generation(report_dir, domain_name)
    _record_final_inventory(report_dir, domain_name, diagnostics)
    return True


def _run_multi_domain_audit_common(audit_context, company_names, unsafe_report_enabled,
                                    audit_label, require_ntds, generate_reports,
                                    single_domain_reporting=None,
                                    single_domain_start_message=None,
                                    single_domain_completion_message=None):
    diagnostics = audit_context.diagnostics
    all_domains = audit_context.all_domains
    _record_diagnostics_domains(diagnostics, all_domains)

    if len(all_domains) <= 1:
        if single_domain_reporting is None:
            return None
        return _run_single_domain_audit(
            single_domain_reporting, company_names, audit_label, generate_reports,
            diagnostics=diagnostics,
            start_message=single_domain_start_message,
            completion_message=single_domain_completion_message,
        )

    print(f"\n{'='*60}")
    print(f"Multiple domains detected: {', '.join(all_domains)}")
    print(f"Running {audit_label} for {len(all_domains)} domains.")
    print(f"{'='*60}\n")

    domain_hashes = audit_context.domain_hashes
    if require_ntds and audit_context.ntds_file_path and not audit_context.ntds_entries_loaded:
        print("Error: No valid entries found in NTDS file.")
        return True

    cross_domain_results = audit_context.cross_domain_results

    cracked_hashes_global = audit_context.cracked_passwords_global if audit_context.hashcat_file_path else None

    for domain in all_domains:
        print(f"\n{'='*60}")
        print(f"Processing domain: {domain}")
        print(f"{'='*60}")

        ntds_data = None
        if domain_hashes:
            ntds_user_hashes, lm_hashes = domain_hashes.get(domain, ({}, {}))
            if ntds_user_hashes:
                ntds_data = (ntds_user_hashes, lm_hashes)
            elif require_ntds:
                print(f"No NTDS hashes found for domain {domain}. Skipping.")
                continue

        neo4j_data = audit_context.get_domain_neo4j_data(domain)

        if audit_context.hashcat_file_path:
            cracked_hashes = cracked_hashes_global
            ntlmv2_hashes = audit_context.get_ntlmv2_hashes_for_domain(domain)
        else:
            cracked_hashes, ntlmv2_hashes = None, None

        accountanalysis = AccountAnalysis(cracked_hashes, ntlmv2_hashes, ntds_data, neo4j_data, diagnostics=diagnostics)

        if require_ntds and not accountanalysis.has_enabled_cracked_accounts():
            print(f"No enabled cracked accounts for {domain}. Skipping password audit.")
            continue

        analysis = Analysis(neo4j_data, cracked_hashes, ntlmv2_hashes, ntds_data, account_analysis=accountanalysis)

        if cross_domain_results:
            from checks.cross_domain.injector import inject_cross_domain_results
            inject_cross_domain_results(accountanalysis, cross_domain_results, ntds_available=bool(ntds_data))

        reporting = Reporting(
            account_analysis=accountanalysis,
            analysis=analysis,
            config=None,
            unsafe_report_enabled=unsafe_report_enabled,
        )

        report_dir = f"report_{domain.lower()}"
        print(f"Generating {audit_label} reports in directory: {report_dir}")

        generate_reports(reporting, company_names, cross_domain_results)

        print(f"{audit_label.capitalize()} reports for {domain} generated in {report_dir}/")
        run_client_report_generation(report_dir, domain)
        _record_final_inventory(report_dir, domain, diagnostics)

    return True


def run_multi_domain_password_audit(audit_context, company_names,
                                     unsafe_report_enabled=False,
                                     single_domain_reporting=None,
                                     single_domain_start_message=None,
                                     single_domain_completion_message=None):
    def generate_reports(reporting, company_names, cross_domain_results):
        reporting.generate_password_audit_report(company_names, 'safe', cross_domain_data=cross_domain_results)
        if unsafe_report_enabled:
            reporting.generate_password_audit_report(company_names, 'unsafe', cross_domain_data=cross_domain_results)

    return _run_multi_domain_audit_common(
        audit_context, company_names, unsafe_report_enabled,
        audit_label="password audit", require_ntds=True, generate_reports=generate_reports,
        single_domain_reporting=single_domain_reporting,
        single_domain_start_message=single_domain_start_message,
        single_domain_completion_message=single_domain_completion_message,
    )


def run_multi_domain_full_audit(audit_context, company_names,
                                 unsafe_report_enabled=False,
                                 single_domain_reporting=None,
                                 single_domain_start_message=None,
                                 single_domain_completion_message=None):
    def generate_reports(reporting, company_names, cross_domain_results):
        reporting.generate_full_report(company_names, cross_domain_data=cross_domain_results)

    return _run_multi_domain_audit_common(
        audit_context, company_names, unsafe_report_enabled,
        audit_label="audit", require_ntds=False, generate_reports=generate_reports,
        single_domain_reporting=single_domain_reporting,
        single_domain_start_message=single_domain_start_message,
        single_domain_completion_message=single_domain_completion_message,
    )


def main():
    parser = argparse.ArgumentParser(description="ADPathFinder")
    
    parser.add_argument('--ad', '--adaudit', action='store_true', help='Perform AD Audit')
    parser.add_argument('--pwd', '--password-audit', type=str, metavar='Company1, Company2',
                      help='Perform Password Audit, requires company names for password category (company1, company2)')
    parser.add_argument('--update-usernames', action='store_true', help='Force update of statistically likely usernames')
    parser.add_argument('-i', '--import', dest='import_file', type=str, nargs='+', help='Import BloodhoundCE data from one or more zip files')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete all BloodHoundCE data and reset the database')
    
    parser.add_argument('-p', '--potfile', type=str, help='Path to the hashcat potfile')
    parser.add_argument('--ntds', type=str, help='Path to the NTDS.dit file (required for password audit)')
    parser.add_argument('-m', '--mark_owned', action='store_true', help='Mark accounts with cracked passwords as owned in Bloodhound-CE and store passwords in Neo4j, displayed in Bloodhound GUI')
    parser.add_argument('--setup-bloodhound-api', action='store_true', help='Configure BloodHound API settings, used for importing and deleting data')
    parser.add_argument('--unsafe-report', action='store_true', help='Generate unsafe reports that include cleartext passwords')
    parser.add_argument('--diagnostics', action='store_true', help='Write diagnostics.json with execution stats')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    
    config = configparser.ConfigParser()
    config_file = 'config.ini'

    if os.path.exists(config_file):
        config.read(config_file)

    resolved = load_resolved_config(config_file)

    if args.pwd and not args.ntds:
        print("Error: Password audit requires NTDS data. Please provide it using the --ntds parameter.")
        sys.exit(1)

    if args.pwd:
        if not args.potfile:
            if not resolved.hashcat_file_path:
                print("Error: Password audit requires a hashcat potfile. Please provide it using the -p parameter.")
                sys.exit(1)
        else:
            if not os.path.isfile(args.potfile):
                print(f"Error: Provided potfile does not exist: {args.potfile}")
                sys.exit(1)
    
    if args.ntds and not os.path.isfile(args.ntds):
        print(f"Error: The specified NTDS file does not exist: {args.ntds}")
        sys.exit(1)
        
    if args.import_file:
        for import_file in args.import_file:
            if not os.path.exists(import_file):
                print(f"Error: BloodHound data file not found: {import_file}")
                sys.exit(1)
        
    if args.setup_bloodhound_api:
        if not os.path.exists(config_file):
            get_valid_neo4j_credentials(resolved, config, config_file)
            resolved = load_resolved_config(config_file)
        bloodhound_username, bloodhound_password = get_valid_bloodhound_credentials(resolved, config, config_file, force=True)
        if bloodhound_username and bloodhound_password:
            print("BloodHound API configuration completed successfully.")
        sys.exit(0)

    conn, bloodhound_username, bloodhound_password, bloodhound_enabled = connect_neo4j_and_load_bloodhound(resolved, config, config_file)

    if args.delete or args.import_file:
        if not bloodhound_enabled or not bloodhound_username or not bloodhound_password:
            resolved = load_resolved_config(config_file)
            bloodhound_username, bloodhound_password = get_valid_bloodhound_credentials(resolved, config, config_file)
            if not bloodhound_username or not bloodhound_password:
                if resolved.bh_configured:
                    print(
                        "BloodHound API is disabled. Set [BLOODHOUND] enabled = True in config.ini "
                        "(or unset ADPF_BLOODHOUND_ENABLED if it's set in your environment), "
                        "or run --setup-bloodhound-api."
                    )
                else:
                    print("BloodHound API is not configured. Run --setup-bloodhound-api first.")
                sys.exit(1)
            bloodhound_enabled = True

        importer = BloodhoundImporter(conn, bloodhound_username=bloodhound_username, bloodhound_password=bloodhound_password, base_url=resolved.bh_url)

        if args.delete:
            standalone_delete = not (args.import_file or args.ad or args.pwd)
            confirmation = input("Are you sure you want to delete all BloodHound data? This action cannot be undone! (yes/no): ").strip().lower()
            if confirmation in ['yes', 'y']:
                print("Deleting all BloodHound data...")

                deletion_success = importer.clear_database()

                if not deletion_success:
                    print("\n[-] Failed to delete BloodHound data. Please check your credentials and try again.")
                    if standalone_delete:
                        conn.close()
                        sys.exit(1)
                else:
                    neo4j_data = Neo4jData(conn)
                    max_attempts = 150  # Maximum number of attempts (150 seconds)
                    attempt = 0
                    print("Verifying data deletion...")

                    while attempt < max_attempts:
                        domain_name = neo4j_data.get_domain_name(force_refresh=True)
                        if domain_name == "Unknown Domain":
                            print("[+] Database successfully cleared. All BloodHound data has been deleted.")
                            print("[+] You can upload new data using the -i parameter.")
                            if standalone_delete:
                                conn.close()
                                sys.exit(0)
                            break
                        else:
                            attempt += 1
                            print(f"Waiting for data to clear... ({attempt}/{max_attempts})", end="\r")
                            time.sleep(1)

                    if attempt >= max_attempts and standalone_delete:
                        print("\nWarning: Data deletion was initiated but some data may still exist in the database.")
                        print("You may need to restart the BloodHound server or manually clear the database.")
                        conn.close()
                        sys.exit(1)
            else:
                print("Deletion aborted by user.")
                if standalone_delete:
                    conn.close()
                    sys.exit(0)
                
        if args.import_file:
            import_success = handle_import_with_check(args, importer, conn)
            if import_success:
                if not args.ad and not args.pwd:
                    conn.close()
                    sys.exit(0)
            else:
                sys.exit(1)
        
    cracked_hashes = None
    ntlmv2_hashes = None
    ntds_hashes = None
    ntds_file_path = None
    hashcat_file_path = None
    excluded_relationships = list(resolved.excluded_relationships)

    if args.potfile:
        hashcat_file_path = args.potfile.strip()
        if not config.has_section('HASHCAT'):
            config.add_section('HASHCAT')
        config['HASHCAT']['file_path'] = hashcat_file_path
        try:
            save_config(config, config_file)
            print("Hashcat configuration updated with the provided potfile.")
        except Exception as e:
            print(f"Failed to update config file: {e}")
    elif resolved.hashcat_file_path:
        hashcat_file_path = resolved.hashcat_file_path
        print(f"Using Hashcat potfile from configuration: {hashcat_file_path}")
    elif args.ad:
        print("Proceeding with domain audit without hashcat potfile.")
        hashcat_file_path = None
    else:
        while True:
            potfile_input = prompt("Enter hashcat potfile path (press Enter to skip): ", completer=path_completer).strip()
            if not potfile_input:
                print("Proceeding without hashcat potfile.")
                hashcat_file_path = None
                break
            elif os.path.isfile(potfile_input):
                hashcat_file_path = potfile_input
                if not config.has_section('HASHCAT'):
                    config.add_section('HASHCAT')
                config['HASHCAT']['file_path'] = hashcat_file_path
                try:
                    save_config(config, config_file)
                    print("Hashcat configuration updated with the provided potfile.")
                except Exception as e:
                    print(f"Failed to update config file: {e}")
            break

    if args.update_usernames:
        from modules.utils import fetch_and_store_usernames
        fetch_and_store_usernames(force_update=True)
        sys.exit(0)

    if args.ntds:
        try:
            ntds_hashes = load_ntds_hashes(args.ntds)
            ntds_file_path = args.ntds  
            print(f"NTDS hashes loaded from: {args.ntds}")
        except Exception as e:
            print(f"Failed to load NTDS hashes: {e}")
            sys.exit(1)
    else:
        if not args.ad:
            while True:
                ntds_input = prompt("Enter path to NTDS.dit file (press Enter to skip): ", completer=path_completer).strip()
                if not ntds_input:
                    ntds_hashes = None
                    ntds_file_path = None
                    break
                elif os.path.isfile(ntds_input):
                    try:
                        ntds_hashes = load_ntds_hashes(ntds_input)
                        ntds_file_path = ntds_input  # Track the file path
                        print(f"NTDS hashes loaded from: {ntds_input}")
                        break
                    except Exception as e:
                        print(f"Failed to load NTDS hashes: {e}")
                        print("Please try again or press Enter to skip.")
                else:
                    print(f"The specified file was not found: {ntds_input}")
        else:
            ntds_hashes = None
            ntds_file_path = None

    diagnostics = None
    if args.diagnostics:
        from .diagnostics import DiagnosticsCollector, compute_audit_mode
        diagnostics = DiagnosticsCollector()
        diagnostics.args = {
            "ad": args.ad, "pwd": args.pwd,
            "ntds": args.ntds is not None, "potfile": args.potfile is not None,
            "unsafe_report": args.unsafe_report,
            "mode": compute_audit_mode(args.ad, args.pwd),
        }

    neo4j_data = Neo4jData(conn, excluded_relationships=excluded_relationships, diagnostics=diagnostics)
    domain_name = neo4j_data.get_domain_name()
    if domain_name == "Unknown Domain":
        print("\nError: No BloodHound data found in the Neo4j database. Please ensure you have uploaded BloodHound data using the BloodHound GUI")
        print("Exiting. Please upload BloodHound data and try again.\n")
        conn.close()
        sys.exit(1)

    audit_context = MultiDomainAuditContext(
        conn=conn,
        unscoped_neo4j_data=neo4j_data,
        excluded_relationships=excluded_relationships,
        hashcat_file_path=hashcat_file_path,
        ntds_file_path=ntds_file_path,
        diagnostics=diagnostics,
    )

    if audit_context.hashcat_file_path:
        cracked_hashes = audit_context.cracked_passwords_global
        ntlmv2_hashes = audit_context.get_ntlmv2_hashes_for_domain(domain_name)
    else:
        cracked_hashes, ntlmv2_hashes = None, None

    if (args.pwd or args.ad) and not cracked_hashes and not ntds_hashes:
        print("Proceeding with limited functionality due to missing or skipped potfile and NTDS data.")

    accountanalysis = AccountAnalysis(cracked_hashes, ntlmv2_hashes, ntds_hashes, neo4j_data, diagnostics=diagnostics)

    user_query = UserQuery(neo4j_data, accountanalysis.cracked_accounts, ntds_hashes)

    analysis = Analysis(neo4j_data, cracked_hashes, ntlmv2_hashes, ntds_hashes, account_analysis=accountanalysis)

    if args.mark_owned:
        if not args.potfile and not hashcat_file_path:
            print("Error: Marking as owned requires potfile data. Please provide it using the --potfile parameter.")
            sys.exit(1)
        
        if not ntds_hashes:
            print("Error: Marking as owned requires NTDS data but none was provided.")
            print("Please provide NTDS data using the --ntds parameter or when prompted.")
            sys.exit(1)
        
        if not ntds_file_path:
            print("Error: NTDS file path was not tracked properly.")
            sys.exit(1)

        print("[*] Marking users as owned and setting passwords in Neo4j!")

        cracked_users_list = list(accountanalysis.cracked_accounts.keys())
        print(f"[*] Total number of cracked accounts to mark as owned: {len(cracked_users_list)}")

        importer = BloodhoundImporter(conn, bloodhound_username=bloodhound_username, bloodhound_password=bloodhound_password, base_url=resolved.bh_url)
        importer.neo4j_data = neo4j_data
        importer.cracked_accounts = accountanalysis.cracked_accounts
        importer.mark_as_owned(cracked_users_list, ntds_file_path)


    reporting = Reporting(
        account_analysis=accountanalysis,
        analysis=analysis,
        config=config,
        unsafe_report_enabled=args.unsafe_report,
    )
    
    should_exit = False

    pwd_company_names = None
    if args.pwd:
        pwd_company_names = [name.strip() for name in args.pwd.split(',') if name.strip()]
        print(f"Using company names for password audit: {', '.join(pwd_company_names)}")
    
    if args.ad:
        if pwd_company_names:
            company_names = pwd_company_names
            print(f"Also using these company names for domain audit: {', '.join(company_names)}")
        else:
            company_names = reporting.get_company_names()

        run_multi_domain_full_audit(
            audit_context, company_names,
            unsafe_report_enabled=args.unsafe_report,
            single_domain_reporting=reporting,
            single_domain_start_message="Generating domain audit reports in directory: {report_dir}"
        )
        should_exit = True

    if args.pwd and pwd_company_names:
        run_multi_domain_password_audit(
            audit_context, pwd_company_names,
            unsafe_report_enabled=args.unsafe_report,
            single_domain_reporting=reporting
        )
        should_exit = True

    if should_exit:
        if diagnostics:
            if not diagnostics.domains:
                diagnostics.domains = [neo4j_data.get_domain_name()]
            report_dir = f"report_{neo4j_data.get_domain_name().lower()}"
            diag_path = os.path.join(report_dir, "diagnostics.json")
            diagnostics.write(diag_path)
            print(f"[+] Diagnostics written to {diag_path}")
        conn.close()
        sys.exit(0)

    while True:
        print("\nMain Menu:")
        if ntds_hashes:
            print("1. Domain Audit & Password Audit")
        else:
            print("1. Domain Audit")
        
        print("2. Password Audit (Not available - NTDS data not provided)" if not ntds_hashes else "2. Password Audit")
        print("3. Check User Details & Path")
        print("4. Exit")
        main_choice = input("Enter your choice: ")

        if main_choice == "1":
            company_names = reporting.get_company_names()
            run_multi_domain_full_audit(
                audit_context, company_names,
                unsafe_report_enabled=False,
                single_domain_reporting=reporting,
                single_domain_start_message="Generating reports in directory: {report_dir}"
            )
            if args.mark_owned and ntds_hashes and ntds_file_path: populate_neo4j_passwords(conn, neo4j_data, accountanalysis, ntds_file_path, config, bloodhound_username, bloodhound_password, bloodhound_url=resolved.bh_url)
        elif main_choice == "2":
            if ntds_hashes:
                company_names = reporting.get_company_names()
                run_multi_domain_password_audit(
                    audit_context, company_names,
                    unsafe_report_enabled=False,
                    single_domain_reporting=reporting,
                    single_domain_completion_message="Password audit reports have been generated in the {report_dir} directory."
                )
                if args.mark_owned and ntds_hashes and ntds_file_path: populate_neo4j_passwords(conn, neo4j_data, accountanalysis, ntds_file_path, config, bloodhound_username, bloodhound_password, bloodhound_url=resolved.bh_url)
            else:
                print("Password Audit is not available as NTDS data was not provided.")
        
        elif main_choice == "3":
            user_query.check_user()
        
        elif main_choice == "4":
            print("Exiting the application. Goodbye!")
            break     
        else:
            print("Invalid choice. Please try again.")

    conn.close()

if __name__ == "__main__":
    main()
