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
if __name__=='__main__':unittest.main()
