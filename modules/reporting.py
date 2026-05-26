import os
import json
import re
from .html_report_generator import HTMLReportGenerator
from .node_type_cache import NodeTypeCache
from .report_json import ReportJsonMixin
from .report_stats import ReportStatsMixin


class Reporting(ReportJsonMixin, ReportStatsMixin):
    def __init__(
        self,
        account_analysis,
        analysis,
        config=None,
        unsafe_report_enabled=False,
    ):
        self.account_analysis = account_analysis
        self.analysis = analysis
        self.output_format = 'safe'
        self.unsafe_report_enabled = unsafe_report_enabled

        self.user_details = {}
        self.likely_usernames = None
        self.cracked_hashes = analysis.cracked_hashes
        self.neo4j_data = analysis.neo4j_data
        self.ntlmv2_hashes = analysis.ntlmv2_hashes
        self.ntds_hashes = analysis.ntds_hashes

        self.domain_name = self.neo4j_data.get_domain_name()
        self.domain_sid = self.neo4j_data.get_domain_sid_pattern()

        self.report_dir = f"report_{self.domain_name.lower()}"
        os.makedirs(self.report_dir, exist_ok=True)
        
        self.type_cache = NodeTypeCache(self.neo4j_data.conn if self.neo4j_data else None)

        self._username_regex = None
        self._username_pattern = None
        self.path_object_details_cache = {}

    def _remove_ansi_escape_sequences(self, text):
        ansi_escape = re.compile(r'''
            \x1B 
            (?:   
                [@-Z\\-_]| 
                \[          
                [0-?]*     
                [ -/]*      
                [@-~]|      
                \].*?(?:\x1B\\|\x07)|  
                \[[0-9;]*[mK]    
            )
        ''', re.VERBOSE)
        return ansi_escape.sub('', text)
    
    def get_company_names(self):
        if self.analysis.ntds_hashes is None:
            return None
            
        company_names = []
        print("\nEnter company name variations to check for in passwords.")
        print("These will be used to identify passwords that include company-related terms and outputted into a unique category.")
        print("Enter each variation on a new line. Press Enter twice when finished.\n")
        
        while True:
            name = input("Enter company name variation (or press enter twice to finish): ").strip()
            if not name:
                if not company_names:
                    print("No company names entered. Skipping company name password checks.")
                break
            company_names.append(name)
        
        return company_names if company_names else None          
 
    def generate_password_audit_report(self, company_names, output_format, cross_domain_data=None):
        if not self.account_analysis.has_enabled_cracked_accounts():
            print(f"No enabled cracked accounts for {self.neo4j_data.get_domain_name()}. Skipping password audit.")
            return None

        original_format = self.output_format
        self.output_format = output_format
        self.account_analysis.set_output_format(output_format)

        ntds_available = self.analysis.ntds_hashes is not None

        # If unsafe format requested but no NTDS data, force safe format
        if output_format == 'unsafe' and not ntds_available:
            print("NTDS data not available. Forcing 'safe' format for password audit.")
            self.output_format = 'safe'
            self.account_analysis.set_output_format('safe')
            output_format = 'safe'
                
        password_audit_report = self.analysis.password_audit(company_names, output_format)

        shared_accounts_report, shared_accounts_summary = self.account_analysis.find_and_display_shared_accounts(output_format)

        combined_report = (
            f"{password_audit_report.rstrip()}\n\n"
            f"{shared_accounts_report.lstrip()}"
        )

        report_data = self._remove_ansi_escape_sequences(combined_report)

        cross_domain_pwd_text = self._render_cross_domain_password_text()
        if cross_domain_pwd_text:
            report_data = f"{report_data.rstrip()}\n\n{cross_domain_pwd_text}"

        self.save_report('password_audit', report_data, 'txt', output_format)

        if not hasattr(self, 'user_details') or not self.user_details:
            self.get_user_details(report_data)

        stats = self.parse_report_statistics(report_data)

        html_generator = HTMLReportGenerator(
            neo4j_data=self.neo4j_data,
            account_analysis=self.account_analysis,
            analysis=self.analysis,
            domain_name=self.domain_name,
            output_format=self.output_format,
            report_dir=self.report_dir,
            user_details=self.user_details,
            stats=stats,
            ntlmv2_hashes=getattr(self, 'ntlmv2_hashes', {}),
            likely_usernames=getattr(self, 'likely_usernames', []),
            cross_domain_data=cross_domain_data
        )
        html_generator.generate_html_report_with_tabs(
            report_data,
            self.analysis.password_length_data,
            f"{self.domain_name.lower()}_password_audit_{output_format}",
            stats,
            shared_accounts_summary=shared_accounts_summary
        )
        
        original_suppress = getattr(self.account_analysis, 'suppress_terminal_output', False)
        self.account_analysis.suppress_terminal_output = True

        _, organised_risk_profiles = self.account_analysis.create_password_risk_profiles(
            shared_accounts_summary=shared_accounts_summary
        )

        self.account_analysis.suppress_terminal_output = original_suppress

        organised_risk_profiles = self._merge_framework_results(organised_risk_profiles)

        password_json_data = self._generate_password_only_json_data(organised_risk_profiles, 'safe')
        password_json_filename = f"{self.domain_name.lower()}_password_audit.json"
        password_json_path = os.path.join(self.report_dir, password_json_filename)
        try:
            with open(password_json_path, 'w', encoding='utf-8') as f:
                json.dump(password_json_data, f, indent=2, ensure_ascii=False)
            print(f"Password audit JSON saved: {password_json_filename}")
        except Exception as e:
            print(f"Error saving password audit JSON report: {e}")

        self.output_format = original_format
        self.account_analysis.set_output_format(original_format)
        self.account_analysis.suppress_terminal_output = original_suppress
        
        return report_data


    def _render_cross_domain_password_text(self):
        if not hasattr(self.account_analysis, '_framework_display_content'):
            return ''

        content = []
        for level, entries in self.account_analysis._framework_display_content.items():
            for entry in sorted(entries, key=lambda e: e['category']):
                if not entry.get('password_audit'):
                    continue
                adapter = entry['check_instance']
                display_method = adapter.get_display_method()
                display_method(entry['results'], '', entry['category'], content, entry['count'], '')

        return '\n'.join(content).strip()

    def _merge_framework_results(self, organised_risk_profiles):
        if hasattr(self.account_analysis, '_framework_categories_for_stats'):
            for level, categories in self.account_analysis._framework_categories_for_stats.items():
                if level not in organised_risk_profiles:
                    organised_risk_profiles[level] = {}
                for category_name, category_data in categories.items():
                    if category_name not in organised_risk_profiles[level]:
                        results = category_data.get('results', {})
                        if isinstance(results, dict):
                            organised_risk_profiles[level][category_name] = results
                            self.account_analysis.category_to_risk_level[category_name] = level
        return organised_risk_profiles

    def _generate_domain_only_json_data(self, organised_risk_profiles, output_format):
        domain_categories = {
            'Non-admin Users with Escalation Paths',
            'Computers with Escalation Paths',
            'User with Unconstrained Delegation',
            'Computer with Unconstrained Delegation', 
            'User with Constrained Delegation',
            'Computer with Constrained Delegation',
            'Computer has Admin Rights from Another Computer',
            'Non-admin User has Admin Rights on a Computer',
            'Default Groups with Privilege Escalation Paths',
            'Common Groups with Privilege Escalation Paths',
            'Computers with WebClient and Escalation Paths',
            'KRBTGT Password Older Than 6 Months',
            'Tier-0 Session on Non-Tier-0 Host'
        }
        
        filtered_risk_profiles = {}
        for level, categories in organised_risk_profiles.items():
            filtered_categories = {}
            for category, entities in categories.items():
                if category in domain_categories:
                    filtered_categories[category] = entities
            if filtered_categories:
                filtered_risk_profiles[level] = filtered_categories

        json_data = self._generate_json_data(filtered_risk_profiles, output_format)

        json_data['password_statistics'] = {}
        json_data['metadata']['audit_type'] = 'domain_only'
        json_data['metadata']['contains_password_data'] = False
        
        return json_data
    
    def generate_full_report(self, company_names, cross_domain_data=None):
        
        domain_name = self.neo4j_data.get_domain_name()
        report_dir = f"report_{domain_name.lower()}"
        os.makedirs(report_dir, exist_ok=True)
        
        all_reports_data = {}
        self.path_object_details_cache = {}

        risk_profiles_by_format = {}

        formats_to_output = ['safe']
        ntds_available = self.analysis.ntds_hashes is not None
        has_cracked_accounts = self.account_analysis.has_enabled_cracked_accounts()

        if ntds_available and has_cracked_accounts and self.unsafe_report_enabled:
            formats_to_output.append('unsafe')
            print("Generating both safe and unsafe reports")
        else:
            print("Generating safe reports only")

        for output_format in formats_to_output:
            self.output_format = output_format
            self.account_analysis.set_output_format(output_format)
            
            _, shared_accounts_summary = self.account_analysis.find_and_display_shared_accounts(output_format)

            risk_profile_report, organised_risk_profiles = self.account_analysis.create_risk_profiles(
                shared_accounts_summary=shared_accounts_summary
            )

            risk_profiles_by_format[output_format] = {
                'organised_risk_profiles': organised_risk_profiles,
                'shared_accounts_summary': shared_accounts_summary
            }
            
            if output_format not in all_reports_data:
                all_reports_data[output_format] = {}
                    
            domain_text = self._remove_ansi_escape_sequences(risk_profile_report)

            all_reports_data[output_format]['domain_audit_text'] = domain_text

            self.save_report('domain_audit', all_reports_data[output_format]['domain_audit_text'], 'txt', output_format)

        json_output_format = 'safe'
        self.output_format = json_output_format
        self.account_analysis.set_output_format(json_output_format)
        
        if json_output_format in risk_profiles_by_format:
            organised_risk_profiles = risk_profiles_by_format[json_output_format]['organised_risk_profiles']
            shared_accounts_summary = risk_profiles_by_format[json_output_format]['shared_accounts_summary']
        else:
            _, shared_accounts_summary = self.account_analysis.find_and_display_shared_accounts(json_output_format)
            _, organised_risk_profiles = self.account_analysis.create_risk_profiles(
                shared_accounts_summary=shared_accounts_summary
            )
        
        organised_risk_profiles = self._merge_framework_results(organised_risk_profiles)

        domain_json_data = self._generate_domain_only_json_data(organised_risk_profiles, json_output_format)
        domain_json_filename = f"{domain_name.lower()}_domain_audit.json"
        domain_json_path = os.path.join(self.report_dir, domain_json_filename)
        try:
            with open(domain_json_path, 'w', encoding='utf-8') as f:
                json.dump(domain_json_data, f, indent=2, ensure_ascii=False)
            print(f"Domain audit JSON saved: {domain_json_filename}")
        except Exception as e:
            print(f"Error saving domain audit JSON report: {e}")
        
        if ntds_available and has_cracked_accounts:
            for output_format in formats_to_output:
                self.output_format = output_format
                self.account_analysis.set_output_format(output_format)

                password_audit_report = self.analysis.password_audit(company_names, output_format)

                shared_accounts_report, _ = self.account_analysis.find_and_display_shared_accounts(output_format)
                
                combined_report = (
                    f"{password_audit_report.rstrip()}\n\n"
                    f"{shared_accounts_report.lstrip()}"
                )
                report_text = self._remove_ansi_escape_sequences(combined_report)

                cross_domain_pwd_text = self._render_cross_domain_password_text()
                if cross_domain_pwd_text:
                    report_text = f"{report_text.rstrip()}\n\n{cross_domain_pwd_text}"

                all_reports_data[output_format]['password_audit_text'] = report_text

                self.save_report('password_audit', all_reports_data[output_format]['password_audit_text'], 'txt', output_format)

                if not hasattr(self, 'user_details') or not self.user_details:
                    self.get_user_details(all_reports_data[output_format]['password_audit_text'])

                stats = self.parse_report_statistics(all_reports_data[output_format]['password_audit_text'])

                html_generator = HTMLReportGenerator(
                    neo4j_data=self.neo4j_data,
                    account_analysis=self.account_analysis,
                    analysis=self.analysis,
                    domain_name=self.domain_name,
                    output_format=self.output_format,
                    report_dir=self.report_dir,
                    user_details=getattr(self, 'user_details', {}),
                    stats=stats,
                    ntlmv2_hashes=getattr(self, 'ntlmv2_hashes', {}),
                    likely_usernames=getattr(self, 'likely_usernames', []),
                    cross_domain_data=cross_domain_data
                )
                html_generator.generate_html_report_with_tabs(
                    all_reports_data[output_format]['password_audit_text'],
                    self.analysis.password_length_data,
                    f"{self.domain_name.lower()}_password_audit_{output_format}",
                    stats
                )
            
            password_json_data = self._generate_password_only_json_data(organised_risk_profiles, json_output_format)
            password_json_filename = f"{domain_name.lower()}_password_audit.json"
            password_json_path = os.path.join(self.report_dir, password_json_filename)
            try:
                with open(password_json_path, 'w', encoding='utf-8') as f:
                    json.dump(password_json_data, f, indent=2, ensure_ascii=False)
                print(f"Password audit JSON saved: {password_json_filename}")
            except Exception as e:
                print(f"Error saving password audit JSON report: {e}")
        elif ntds_available:
            print(f"\nNo enabled cracked accounts for {domain_name}. Skipping password audit.")
        else:
            print("\nNTDS data not provided. Skipping password audit.")
        
        print(f"\nAll reports have been generated in the '{report_dir}' directory.")
        
        self.output_format = 'safe'
        self.account_analysis.set_output_format('safe')

        return all_reports_data.get('safe', {}).get('password_audit_text'), all_reports_data.get('safe', {}).get('domain_audit_text')
    
    def _generate_password_only_json_data(self, organised_risk_profiles, output_format):
        print("Generating password JSON data...")
        password_categories = {
            'Admin with Weak Password',
            'Non-admin with Weak Password', 
            'Kerberoastable with Admin privileges and Weak Password',
            'AS-REP Roastable with Admin privileges and Weak Password',
            'Non-admin Kerberoastable with Weak Password',
            'Non-admin AS-REP Roastable with Weak Password',
            'User with Weak Password and Unconstrained Delegation',
            'User with Weak Password and Constrained Delegation',
            'Account with Shared Password'
        }
        
        filtered_risk_profiles = {}
        for level, categories in organised_risk_profiles.items():
            filtered_categories = {}
            for category, entities in categories.items():
                if category in password_categories:
                    filtered_categories[category] = entities
            if filtered_categories:
                filtered_risk_profiles[level] = filtered_categories
        
        json_data = self._generate_json_data(filtered_risk_profiles, output_format)

        json_data['metadata']['audit_type'] = 'password_only'
        json_data['metadata']['contains_password_data'] = True

        json_data['domain_summary'] = {}
        
        return json_data

    def save_report(self, report_type, report_content, format_type, output_format):
        filepath = self.get_report_path(report_type, output_format, format_type)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(report_content)
            
    def get_report_path(self, report_type, output_format, extension):
        if output_format == 'unsafe':
            filename = f"{self.domain_name.lower()}_{report_type}_unsafe.{extension}"
        else:
            filename = f"{self.domain_name.lower()}_{report_type}.{extension}"
        return os.path.join(self.report_dir, filename)
