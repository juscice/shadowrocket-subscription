#!/usr/bin/env python3
"""Offline release audit: mirrored dependencies, source merge, PCRE and JS syntax."""
import hashlib,json,subprocess,concurrent.futures
from pathlib import Path
import update as u
root=u.ROOT
full=(root/'dist/shadowrocket.conf').read_text();ad=(root/'dist/adblock.sgmodule').read_text();enhance=(root/'dist/enhance.sgmodule').read_text()
u.validate(full,ad,enhance)
refs={}
for text in (full,ad,enhance):refs.update(u.remote_references(text))
raw='https://raw.githubusercontent.com/'+u.CONF['owner']+'/'+u.CONF['repository']+'/'+u.CONF['branch']+'/'
for url,(_,kind) in refs.items():
    if not url.startswith(raw):raise ValueError('external dependency not mirrored: '+url)
    path=root/url[len(raw):]
    if not path.is_file():raise ValueError('missing dependency: '+str(path))
    if kind!='script':u.validate_remote_content(path.read_text(),kind)
report=json.loads((root/'dist/update-report.json').read_text())
if any(r['status']=='unavailable' for r in report['references']):raise ValueError('unavailable source')
routing=u.active(u.read_sections(full)['[Rule]'])
if len(routing)!=len(set(routing)):raise ValueError('duplicate full routing rows')
# Domain-only first-match regression checks; flatten mirrored sets in their actual order.
expanded=[]
for row in routing:
    f=row.split(',')
    if f[0]=='RULE-SET':
        for inner in u.active((root/f[1][len(raw):]).read_text().splitlines()):
            k=inner.split(',')
            if k[0] in {'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD'}:expanded.append((k[0],k[1],f[2]))
    elif f[0] in {'DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD'}:expanded.append(tuple(f[:3]))
def policy(host):
    for kind,target,value in expanded:
        if (kind=='DOMAIN' and host==target) or (kind=='DOMAIN-SUFFIX' and (host==target or host.endswith('.'+target))) or (kind=='DOMAIN-KEYWORD' and target in host):return value
expected={'dns.weixin.qq.com':'DIRECT','dns.weixin.qq.com.cn':'DIRECT','api.openai.com':'🤖️ 人工智能','gemini.google.com':'🔍 谷歌服务','imap.gmail.com':'📧 邮件服务','courier.push.apple.com':'🍎 苹果推送','www.hsbc.com.hk':'🏦 汇丰香港','www.bochk.com':'🏦 香港银行','trade.futunn.com':'📈 券商服务','deepseek.com':'DIRECT','translate.googleapis.com':'📹 YouTube','github.com':'🚀 策略选择'}
for host,want in expected.items():
    got=policy(host)
    if got!=want:raise ValueError(f'routing regression {host}: {got} != {want}')
for host in u.CONF.get('bank_exact_hosts', []):
    if policy(host) != 'DIRECT':raise ValueError('bank app host is not direct: '+host)
for host in ('hcz.pingan.com','hcz-static.pingan.com.cn'):
    if policy(host) != 'DIRECT':raise ValueError('Ping An car owner host is not direct: '+host)
    for text in (full,ad,enhance):
        exclusions=u.financial_exclusions(text)
        if not any(host==r[1:] or host.endswith('.'+r[1:]) for r in exclusions if not r.startswith('-*.')):
            raise ValueError('Ping An car owner host may be decrypted: '+host)
for text in (full,ad,enhance):
    required=u.financial_exclusions(full)
    if not required <= u.financial_exclusions(text):raise ValueError('module missing financial exclusions')
    if u.apply_financial_exclusions(text,required) != text:raise ValueError('contradictory financial MITM host')
    for section,rows in u.read_sections(text).items():
        entries=u.active(rows)
        if len(entries)!=len(set(entries)):raise ValueError('duplicate entries in '+section)
    if any(u.deduplicate_url_sections(text)[1].values()):raise ValueError('duplicate HTTP(S) matcher coverage')
patterns=set()
for text in (full,ad,enhance):
    for row in u.active(u.read_sections(text).get('[Script]',[])):
        pattern=u.attr(row,'pattern')
        if pattern:patterns.add(pattern)
    for section in ('[URL Rewrite]','[Map Local]','[Body Rewrite]'):
        for row in u.active(u.read_sections(text).get(section, [])):
            fields=row.split()
            patterns.add(fields[1] if section=='[Body Rewrite]' else fields[0])
for pattern in patterns:
    result=subprocess.run(['rg','--pcre2','-e',pattern],input='',text=True,capture_output=True)
    if result.returncode not in (0,1):raise ValueError('invalid HTTP pattern: '+pattern+' '+result.stderr)
def check_js(path):
    r=subprocess.run(['node','--check',str(path)],capture_output=True,text=True,timeout=15)
    if r.returncode:raise ValueError('invalid JS '+str(path))
scripts=list((root/'upstream/scripts').glob('*.js'))
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(check_js,scripts))
print(json.dumps({'dependencies':len(refs),'scripts':len(scripts),'http_patterns':len(patterns),'routing_samples':len(expected),'ad_rules':report['ad_rules'],'routing_merge':report.get('routing_merge')},ensure_ascii=False))
