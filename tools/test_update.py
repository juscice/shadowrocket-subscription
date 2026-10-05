import importlib.util, tempfile, unittest, urllib.error
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('update',Path(__file__).with_name('update.py'))
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
class UpdateTests(unittest.TestCase):
    def test_ipv6_type_and_cidr_normalization(self):
        self.assertEqual(u.canonical_rule('IP-CIDR,240e:928:1400:10::25/128'),'IP-CIDR6,240e:928:1400:10::25/128,REJECT,no-resolve')
        self.assertEqual(u.canonical_rule('IP-CIDR,203.107.1.1/24'),'IP-CIDR,203.107.1.0/24,REJECT,no-resolve')
    def test_failure_keeps_last_successful_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source.js';p.write_text('$done({});')
            with patch.object(u.urllib.request,'urlopen',side_effect=urllib.error.URLError('unavailable')):
                r=u.fetch('https://example.invalid/script.js',p,script=True)
            self.assertEqual(r['status'],'fallback');self.assertEqual(p.read_text(),'$done({});')
    def test_initial_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source.js'
            with patch.object(u.urllib.request,'urlopen',side_effect=urllib.error.URLError('unavailable')):
                r=u.fetch('https://example.invalid/script.js',p,script=True)
            self.assertEqual(r['status'],'unavailable');self.assertFalse(p.exists())
    def test_invalid_core_is_rejected(self):
        with self.assertRaises(ValueError):u.core_source_rules('FINAL,DIRECT',{'name':'core'})
        with self.assertRaises(ValueError):u.core_source_rules('',{'name':'core'})
    def test_weread_cannot_be_disabled(self):
        full=(u.ROOT/'profiles/full.conf').read_text();ad=(u.ROOT/'profiles/adblock.sgmodule').read_text();f=(u.ROOT/'profiles/enhance.sgmodule').read_text()
        f=f.replace('member_wxds = type=http-response','member_wxds = type=http-response',1)
        row=next(l for l in f.splitlines() if l.startswith('member_wxds ='))
        f=f.replace(row,row.replace('enable=true','enable=false'))
        with self.assertRaisesRegex(ValueError,'WeRead'):u.validate(full,ad,f)
    def test_remote_mock_is_discovered_and_validated(self):
        row = '^https://api.example.com/ads data-type=file data="https://example.com/mock.json"'
        refs = u.remote_references(row)
        self.assertEqual(len(refs), 1)
        rel, kind = next(iter(refs.values()))
        self.assertTrue(rel.startswith('resources/'))
        self.assertEqual(kind, 'json')
        with self.assertRaises(ValueError): u.validate_remote_content('<html>broken</html>', kind)
        u.validate_remote_content('{"data":[]}', kind)
    def test_malformed_rules_keep_good_cache(self):
        import io
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'rules.list'; p.write_text('DOMAIN,example.com\n')
            with patch.object(u.urllib.request, 'urlopen', return_value=io.BytesIO(b'{"error":"not rules"}')):
                r = u.fetch('https://example.com/rules', p, content_kind='rules')
            self.assertEqual(r['status'], 'fallback')
            self.assertEqual(p.read_text(), 'DOMAIN,example.com\n')
    def test_invalid_initial_mock_has_no_usable_cache(self):
        import io
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'mock.json'
            with patch.object(u.urllib.request, 'urlopen', return_value=io.BytesIO(b'not json')):
                r = u.fetch('https://example.com/mock.json', p, content_kind='json')
            self.assertEqual(r['status'], 'unavailable'); self.assertFalse(p.exists())
    def test_shared_app_services_are_not_ad_targets(self):
        full = (u.ROOT/'profiles/full.conf').read_text()
        rules = ['DOMAIN,ad%d.example.net,REJECT' % i for i in range(110)]
        bad = ['DOMAIN,api.biliapi.net,REJECT',
               'DOMAIN-SUFFIX,firebaseinstallations.googleapis.com,REJECT',
               'DOMAIN-SUFFIX,iciba.com,REJECT',
               'AND,((DOMAIN-KEYWORD,volc)),REJECT']
        result = u.optimize(rules + bad, full)
        self.assertFalse(set(result) & set(bad))
    def test_ai_default_uses_main_selection(self):
        full = (u.ROOT/'profiles/full.conf').read_text()
        row = next(l for l in full.splitlines() if l.startswith('🤖️ 人工智能 ='))
        self.assertEqual(row.split('=',1)[1].strip().split(',')[1], '🚀 策略选择')
    def test_undefined_policy_is_rejected(self):
        full = (u.ROOT/'profiles/full.conf').read_text().replace('FINAL,🚀 策略选择', 'FINAL,missing-group')
        ad = (u.ROOT/'profiles/adblock.sgmodule').read_text()
        feature = (u.ROOT/'profiles/enhance.sgmodule').read_text()
        with self.assertRaisesRegex(ValueError, 'undefined routing'):
            u.validate_public_contract(full, ad, feature)
    def test_private_certificate_is_rejected(self):
        full = (u.ROOT/'profiles/full.conf').read_text().replace('[MITM]', '[MITM]\nca-p12=private-certificate')
        ad = (u.ROOT/'profiles/adblock.sgmodule').read_text()
        feature = (u.ROOT/'profiles/enhance.sgmodule').read_text()
        with self.assertRaisesRegex(ValueError, 'private certificate'):
            u.validate_public_contract(full, ad, feature)
if __name__=='__main__':unittest.main()
