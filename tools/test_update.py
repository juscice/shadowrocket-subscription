import importlib.util, tempfile, unittest, urllib.error, re
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
    def test_routing_does_not_become_ad_blocking(self):
        self.assertEqual(u.canonical_routing_rule('DOMAIN,MAIL.Example.COM.,DIRECT'), 'DOMAIN,mail.example.com')
        self.assertEqual(u.canonical_routing_rule('IP-CIDR,10.1.2.3/8,no-resolve'), 'IP-CIDR,10.0.0.0/8,no-resolve')
        with self.assertRaises(ValueError): u.canonical_routing_rule('FINAL,DIRECT')
    def test_routing_dedup_suffix_and_network_coverage(self):
        rows = ['DOMAIN,api.example.com', 'DOMAIN-SUFFIX,example.com',
                'DOMAIN-SUFFIX,sub.example.com', 'DOMAIN-SUFFIX,example.com',
                'IP-CIDR,10.0.0.0/8,no-resolve', 'IP-CIDR,10.1.0.0/16,no-resolve']
        self.assertEqual(u.deduplicate_routing(rows), ['DOMAIN-SUFFIX,example.com', 'IP-CIDR,10.0.0.0/8,no-resolve'])
    def test_routing_failure_keeps_valid_cache(self):
        import io
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source.list';p.write_text('DOMAIN-SUFFIX,bank.example.com\n')
            with patch.object(u.urllib.request,'urlopen',return_value=io.BytesIO(b'FINAL,REJECT')):
                result=u.fetch('https://example.com/list',p,content_kind='routing')
            self.assertEqual(result['status'],'fallback')
            self.assertEqual(p.read_text(),'DOMAIN-SUFFIX,bank.example.com\n')
    def test_precise_policy_exception_survives_broad_fallback(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            sources=[{'name':'push','policy':'PUSH','urls':['https://example.com/push']},
                     {'name':'apple','policy':'APPLE','urls':['https://example.com/apple']}]
            cache=Path(d);(cache/'routing').mkdir()
            for url,rows in [('https://example.com/push','DOMAIN-SUFFIX,push.apple.com\n'),
                             ('https://example.com/apple','DOMAIN-SUFFIX,apple.com\nDOMAIN-SUFFIX,push.apple.com\n')]:
                (cache/'routing'/(hashlib.sha256(url.encode()).hexdigest()[:20]+'.list')).write_text(rows)
            with patch.object(u,'CACHE',cache),patch.object(u,'ROOT',cache),patch.object(u,'CONF',{'routing_sources':sources}):
                rows,_,counts=u.build_routing(True)
            self.assertIn('DOMAIN-SUFFIX,push.apple.com,PUSH',rows)
            self.assertIn('DOMAIN-SUFFIX,apple.com,APPLE',rows)
            self.assertNotIn('DOMAIN-SUFFIX,push.apple.com,APPLE',rows)
    def test_new_groups_have_portable_defaults(self):
        full=(u.ROOT/'profiles/full.conf').read_text()
        for name in ['📧 邮件服务','🍎 苹果推送','📈 券商服务','🔍 谷歌服务']:
            row=next(l for l in full.splitlines() if l.startswith(name+' ='))
            self.assertEqual(row.split('=',1)[1].strip().split(',')[1],'🚀 策略选择')
        for name in ['🏦 汇丰香港','🏦 香港银行']:
            row=next(l for l in full.splitlines() if l.startswith(name+' ='))
            self.assertEqual(row.split('=',1)[1].strip().split(',')[1],'DIRECT')
class SplashRegressionTests(unittest.TestCase):
    def test_splash_routes_and_conflicting_rejects(self):
        urls = [
            'https://g-acs.m.goofish.com/gw/mtop.taobao.idlecommerce.splash.ads/1.0/?data=x',
            'https://acs.m.goofish.com/gw/mtop.idle.ad.expose/1.0/',
            'https://g-acs.m.goofish.com/gw/mtop.taobao.idlecommerce.splash/1.0/',
            'https://acs.m.taobao.com/gw/mtop.fliggy.crm.screen.availablesplashstrategies/1.0/',
            'https://mapi.dianping.com/mapi/operating/loadsplashconfig?cityId=2',
            'https://m.ctrip.com/restapi/soa2/13916/scjson/tripAds?os=ios',
        ]
        for name in ('full.conf', 'adblock.sgmodule'):
            sections=u.read_sections((u.ROOT/'profiles'/name).read_text())
            # These endpoints have exactly one replacement, no stale blank response.
            maps=u.active(sections['[Map Local]'])
            rewrites=u.active(sections['[URL Rewrite]'])
            for url in urls:
                matches=[r for r in maps if re.search(r.split()[0],url)]
                self.assertEqual(len(matches),1,(name,url,matches))
                self.assertIn('data="{}"',matches[0])
                for row in rewrites:
                    if any(host in row for host in ('goofish','dianping','ctrip','fliggy')):
                        self.assertIsNone(re.search(row.split()[0],url),(name,row,url))
    def test_patch_preserves_business_endpoints_and_qixin_mitm(self):
        business=[
            'https://m.ctrip.com/restapi/soa2/13916/json/getAppConfig',
            'https://m.ctrip.com/restapi/soa2/13916/json/createOrder',
            'https://acs.m.taobao.com/gw/mtop.fliggy.trade.order.create/1.0/',
            'https://acs.m.goofish.com/gw/mtop.taobao.idle.item.detail/1.0/',
            'https://appc-v6.qixin.com/v4/enterprise/getBasicInfo',
        ]
        for name in ('full.conf','adblock.sgmodule'):
            sections=u.read_sections((u.ROOT/'profiles'/name).read_text())
            patches=[r for r in u.active(sections['[Map Local]']) if any(x in r for x in ('[^/?]*splash', 'availablesplashstrategies', 'loadsplashconfig', '[^?]*'))]
            for url in business:
                self.assertFalse(any(re.search(r.split()[0],url) for r in patches),(name,url))
            material='https://qxb-minicode-pic-osscache.qixin.com/web/test.jpg'
            rewrite=u.active(sections['[URL Rewrite]'])[0]
            self.assertIsNotNone(re.search(rewrite.split()[0],material))
            self.assertIn('qxb-minicode-pic-osscache.qixin.com', ''.join(sections['[MITM]']))

class DedupRegressionTests(unittest.TestCase):
    def test_reject_pair_keeps_both_protocols(self):
        original='[URL Rewrite]\n^https://ads.example/a - reject\n^https?://ads.example/a - reject\n'
        result, count=u.deduplicate_url_sections(original)
        rows=u.active(u.read_sections(result)['[URL Rewrite]'])
        self.assertEqual(len(rows),1)
        self.assertEqual(count['removed'],1)
        for url in ('http://ads.example/a','https://ads.example/a'):
            self.assertTrue(re.search(rows[0].split()[0],url))
        self.assertEqual(u.deduplicate_url_sections(result)[0],result)
    def test_conflicting_map_exception_keeps_original_priority(self):
        original='[Map Local]\n^https://api.example/ads data-type=text data="{}"\n^https?://api.example/ads/special data-type=tiny-gif\n^https?://api.example/ads data-type=text data="{}"\n'
        result,count=u.deduplicate_url_sections(original)
        def first(text,url):
            return next(r.split(None,1)[1] for r in u.active(u.read_sections(text)['[Map Local]']) if re.search(r.split()[0],url))
        for url in ('http://api.example/ads','https://api.example/ads','http://api.example/ads/special','https://api.example/ads/special'):
            self.assertEqual(first(original,url),first(result,url))
        self.assertEqual(count['protocol_overlap_resolved'],1)
        self.assertEqual(u.deduplicate_url_sections(result)[0],result)
    def test_distinct_actions_and_body_order_are_preserved(self):
        text='[URL Rewrite]\n^https://api.example/a - reject\n^https?://api.example/a - reject-drop\n[Body Rewrite]\nhttp-response ^https://api.example/a old new\nhttp-response ^https?://api.example/a new final\nhttp-response ^https?://api.example/a old new\n'
        result,count=u.deduplicate_url_sections(text)
        self.assertEqual(u.active(u.read_sections(result)['[URL Rewrite]']),u.active(u.read_sections(text)['[URL Rewrite]']))
        rows=u.active(u.read_sections(result)['[Body Rewrite]'])
        self.assertEqual(rows[1],'http-response ^https?://api.example/a new final')
        self.assertEqual(rows[2],'http-response ^http://api.example/a old new')
        self.assertEqual(count['removed'],0)

if __name__=='__main__':unittest.main()
