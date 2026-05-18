"""Tests for ADCS and rewritten relationship PowerShell command generation."""
import unittest

from modules.shared_powershell import PowerShellCommandGenerator

class TestADCSCommands(unittest.TestCase):
    """Verify _generate_adcs_command produces valid PowerShell for each ESC variant."""

    def setUp(self):
        self.gen = PowerShellCommandGenerator('DC01.test.local', 'test.local', 'S-1-5-21-111-222-333')
        self.source_user = 'jsmith'
        self.target_user = 'TEST-CA'
        self.source_sid = 'S-1-5-21-111-222-333-1001'
        self.target_detail = {'sid': 'S-1-5-21-111-222-333-2001', 'dn': 'CN=TEST-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local'}

    def _call(self, relationship):
        return self.gen._generate_adcs_command(relationship, self.source_user, self.target_user, self.source_sid, self.target_detail)

    def test_all_esc_variants_return_string(self):
        """Every ADCS relationship should return a non-empty string."""
        relationships = [
            'ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4',
            'ADCSESC6a', 'ADCSESC6b', 'ADCSESC7',
            'ADCSESC9a', 'ADCSESC9b', 'ADCSESC10a', 'ADCSESC10b',
            'ADCSESC8', 'CoerceAndRelayNTLMToADCS',
            'ManageCA', 'ManageCertificates',
            'ADCSESC5', 'ADCSESC11', 'ADCSESC12', 'ADCSESC13',
        ]
        for rel in relationships:
            result = self._call(rel)
            self.assertIsInstance(result, str, f"{rel} did not return a string")
            self.assertGreater(len(result), 50, f"{rel} returned unexpectedly short output")

    def test_preamble_present(self):
        """All commands should start with the shared preamble."""
        for rel in ['ADCSESC1', 'ManageCA', 'ADCSESC10a', 'ADCSESC8']:
            result = self._call(rel)
            self.assertIn('Import-Module ActiveDirectory', result)
            self.assertIn('configurationNamingContext', result)
            self.assertIn('pKIEnrollmentService', result)

    def test_esc1_checks_subject_flag(self):
        result = self._call('ADCSESC1')
        self.assertIn('msPKI-Certificate-Name-Flag', result)
        self.assertIn('Enrollee Supplies Subject', result)
        self.assertIn('Vulnerable to ESC1', result)

    def test_esc2_checks_any_purpose(self):
        result = self._call('ADCSESC2')
        self.assertIn('Any Purpose / No EKU', result)
        self.assertIn('Vulnerable to ESC2', result)

    def test_esc3_checks_cra(self):
        result = self._call('ADCSESC3')
        self.assertIn('Certificate Request Agent', result)

    def test_esc4_checks_write_perms(self):
        result = self._call('ADCSESC4')
        self.assertIn('GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty', result)
        self.assertIn('template ACL abuse', result)

    def test_esc6_checks_editf(self):
        result = self._call('ADCSESC6a')
        self.assertIn('EDITF_ATTRIBUTESUBJECTALTNAME2', result)
        # 6a and 6b should produce the same output
        self.assertEqual(self._call('ADCSESC6a'), self._call('ADCSESC6b'))

    def test_esc9_checks_no_security_extension(self):
        result = self._call('ADCSESC9a')
        self.assertIn('0x80000', result)
        self.assertIn('No Security Extension', result)

    def test_esc10_runs_on_dc(self):
        """ESC10 must query DCs remotely, not localhost."""
        result = self._call('ADCSESC10a')
        self.assertIn('Get-ADDomainController', result)
        self.assertIn('Invoke-Command', result)
        self.assertIn('StrongCertificateBindingEnforcement', result)
        # HKLM reads must be inside the $regBlock that runs via Invoke-Command on the DC
        self.assertIn('$regBlock', result)
        # The Invoke-Command should target $dc.HostName
        self.assertIn('Invoke-Command -ComputerName $dc.HostName -ScriptBlock $regBlock', result)

    def test_esc8_checks_web_enrollment(self):
        result = self._call('ADCSESC8')
        self.assertIn('WebAdministration', result)
        self.assertIn('CertSrv', result)
        # CoerceAndRelayNTLMToADCS should produce the same check
        self.assertEqual(result, self._call('CoerceAndRelayNTLMToADCS'))

    def test_manage_ca_and_certificates_deduplicated(self):
        """ManageCA and ManageCertificates should differ only in the relationship name."""
        ca = self._call('ManageCA')
        certs = self._call('ManageCertificates')
        self.assertIn('ManageCA', ca)
        self.assertIn('ManageCertificates', certs)
        # Core logic should be identical after the header line (first differing line)
        ca_lines = ca.split('\n')
        certs_lines = certs.split('\n')
        # Find the first line that differs (the Write-Output header), everything after should match
        first_diff = next(i for i, (a, b) in enumerate(zip(ca_lines, certs_lines)) if a != b)
        self.assertEqual(ca_lines[first_diff + 1:], certs_lines[first_diff + 1:])

    def test_manage_ca_filters_by_target(self):
        result = self._call('ManageCA')
        self.assertIn("$ca.Name -ne 'TEST-CA'", result)

    def test_fallback_handles_unknown_esc(self):
        result = self._call('ADCSESC13')
        self.assertIn('ADCSESC13', result)
        self.assertIn('Published Templates', result)

    def test_server_flag_in_preamble(self):
        result = self._call('ADCSESC1')
        self.assertIn('-server "test.local"', result)

    def test_cross_esc_detection_block(self):
        """ESC1-3, ESC9 checks should include also-vulnerable cross-reference."""
        for rel in ['ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC9a']:
            result = self._call(rel)
            self.assertIn('$also', result, f"{rel} missing cross-ESC detection")
            self.assertIn('Also vulnerable to', result, f"{rel} missing cross-ESC note")

class TestRewrittenRelationshipCommands(unittest.TestCase):
    """Test the rewritten CanRDP, CanPSRemote, ExecuteDCOM, AdminTo, HasSession, SQLAdmin, Contains."""

    def setUp(self):
        self.gen = PowerShellCommandGenerator('DC01.test.local', 'test.local', 'S-1-5-21-111-222-333')
        self.source_sid = 'S-1-5-21-111-222-333-1001'
        self.target_sid = 'S-1-5-21-111-222-333-2001'
        self.target_detail = {'sid': self.target_sid, 'dn': 'CN=WS01,CN=Computers,DC=test,DC=local', 'name': 'WS01$', 'type': 'Computer'}

    def _call(self, relationship):
        return self.gen.generate_relationship_command(
            relationship, 'jsmith@test.local', 'WS01$@test.local',
            {'sid': self.source_sid}, self.target_detail, self.source_sid
        )

    def test_canrdp_uses_invoke_command(self):
        result = self._call('CanRDP')
        self.assertIn('Invoke-Command', result)
        self.assertIn('Remote Desktop Users', result)

    def test_canpsremote_uses_invoke_command(self):
        result = self._call('CanPSRemote')
        self.assertIn('Invoke-Command', result)
        self.assertIn('Remote Management Users', result)

    def test_executedcom_uses_invoke_command(self):
        result = self._call('ExecuteDCOM')
        self.assertIn('Invoke-Command', result)
        self.assertIn('Distributed COM Users', result)

    def test_adminto_uses_invoke_command(self):
        result = self._call('AdminTo')
        self.assertIn('Invoke-Command', result)
        self.assertIn('Administrators', result)

    def test_hassession_provides_guidance(self):
        result = self._call('HasSession')
        self.assertIn('query user', result)
        self.assertIn('LastLogonDate', result)

    def test_sqladmin_checks_spns(self):
        result = self._call('SQLAdmin')
        self.assertIn('MSSQLSvc/', result)
        self.assertIn('IS_SRVROLEMEMBER', result)

    def test_contains_checks_dn_hierarchy(self):
        result = self._call('Contains')
        self.assertIn('DistinguishedName', result)
        self.assertIn('Contains: Yes', result)

    def test_no_placeholder_strings_remain(self):
        """None of these should return a bare description string anymore."""
        for rel in ['AdminTo', 'HasSession', 'SQLAdmin', 'Contains']:
            result = self._call(rel)
            self.assertIn('Import-Module ActiveDirectory', result, f"{rel} still a placeholder")
