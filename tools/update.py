#!/usr/bin/env python3
"""Refresh the approved core and actual remote references; never execute scripts."""
from __future__ import annotations
import argparse, concurrent.futures, hashlib, ipaddress, json, os, re, subprocess, sys, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / 'upstream'
CONF = json.loads((ROOT / 'sources.json').read_text())

def read_sections(text):
    out = {}; name = 'preamble'; out[name] = []
    for line in text.splitlines():
        if re.fullmatch(r'\[[^]]+\]', line.strip()):
            name = line.strip(); out.setdefault(name, [])
        else: out[name].append(line)
    return out

def active(lines):
    return [l.strip() for l in lines if l.strip() and not l.lstrip().startswith(('#', '//'))]

def replace_section(text, section, content):
    start = text.index(section + '\n') + len(section) + 1
    end = text.find('\n[', start)
    if end < 0: end = len(text)
    return text[:start] + content.rstrip() + '\n' + text[end:]

def canonical_rule(line):
    f = [x.strip() for x in line.split(',')]
    if f[0] not in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6'}:
        raise ValueError('unsupported upstream core rule: ' + f[0])
    if len(f) < 2: raise ValueError('missing rule target')
    if f[0].startswith('DOMAIN'):
        f[1] = f[1].lower().rstrip('.')
        if not f[1] or any(c in f[1] for c in '\r\n <>'): raise ValueError('bad domain')
    else:
        n = ipaddress.ip_network(f[1], strict=False)
        f[0] = 'IP-CIDR' if n.version == 4 else 'IP-CIDR6'; f[1] = str(n)
    f = f[:2] + ['REJECT'] + (['no-resolve'] if f[0].startswith('IP-CIDR') else [])
    return ','.join(f)

def attr(line, key):
    m = re.search(r'\b' + re.escape(key) + r'\s*=\s*(.*?)(?=,\s*[a-z-]+\s*=|$)', line)
    return m[1].strip() if m else None

def validate_remote_content(text, kind):
    if kind == 'json':
        json.loads(text)
    elif kind in {'rules', 'domains'}:
        lines = active(text.splitlines())
        if not lines:
            raise ValueError('empty rule set')
        allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
                   'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'USER-AGENT', 'URL-REGEX',
                   'GEOIP', 'AND', 'OR', 'NOT', 'DEST-PORT', 'SRC-PORT', 'PROTOCOL'}
        for line in lines:
            fields = [f.strip() for f in line.split(',')]
            if kind == 'domains':
                if ',' in line or not re.fullmatch(r'[+.\-*a-zA-Z0-9_:]+', line):
                    raise ValueError('invalid domain set entry')
            elif len(fields) < 2 or fields[0] not in allowed or not fields[1]:
                raise ValueError('invalid rule set entry')
            elif fields[0] in {'IP-CIDR', 'IP-CIDR6'}:
                ipaddress.ip_network(fields[1], strict=False)


def remote_references(text):
    refs = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(('#', '//')):
            continue
        url = attr(line, 'script-path')
        if url and url.startswith('https://'):
            refs[url] = ('scripts/' + hashlib.sha256(url.encode()).hexdigest()[:20] + '.js', 'script')
        if line.startswith(('RULE-SET,', 'DOMAIN-SET,')):
            fields = line.split(','); url = fields[1].strip()
            if url.startswith('https://'):
                refs[url] = ('rules/' + hashlib.sha256(url.encode()).hexdigest()[:20] + '.list',
                             'domains' if fields[0] == 'DOMAIN-SET' else 'rules')
        # Map Local uses space-delimited attributes, rather than script commas.
        match = re.search(r'\bdata-type\s*=\s*file\b.*?\bdata\s*=\s*"?(https://[^"\s]+)', line)
        if match:
            url = match[1]
            if not url.split('?', 1)[0].endswith('.json'):
                raise ValueError('unreviewed remote mock format: ' + url)
            refs[url] = ('resources/' + hashlib.sha256(url.encode()).hexdigest()[:20] + '.json', 'json')
    return refs


def fetch(url, target, offline=False, script=False, content_kind=None):
    try:
        if not offline:
            req = urllib.request.Request(url, headers={'User-Agent': 'Shadowrocket-subscription-updater/1.0'})
            with urllib.request.urlopen(req, timeout=25) as response:
                body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024 or not body.strip(): raise ValueError('empty or oversized source')
            text = body.decode('utf-8-sig')
            if re.match(r'\s*(<!doctype|<html)', text, re.I): raise ValueError('HTML instead of rule/script')
            if content_kind: validate_remote_content(text, content_kind)
            if script:
                tmp = target.with_suffix('.candidate.js'); tmp.parent.mkdir(parents=True, exist_ok=True); tmp.write_text(text)
                check = subprocess.run(['node', '--check', str(tmp)], capture_output=True, text=True, timeout=15)
                tmp.unlink()
                if check.returncode: raise ValueError('JavaScript syntax check failed')
            target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text)
        if not target.exists(): raise ValueError('no successful cached version')
        if content_kind: validate_remote_content(target.read_text(), content_kind)
        return {'url': url, 'status': 'cached' if offline else 'ok', 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    except Exception as exc:
        valid_cache = target.exists()
        if valid_cache and content_kind:
            try: validate_remote_content(target.read_text(), content_kind)
            except Exception: valid_cache = False
        return {'url': url, 'status': 'fallback' if valid_cache else 'unavailable', 'error': str(exc)}

def core_source_rules(text, source):
    lines = active(text.splitlines())
    if 'SDK endpoint subset' in source['name']:
        selector = re.compile(CONF['sdk_selector'], re.I); lines = [l for l in lines if selector.search(l)]
    rules = [canonical_rule(l) for l in lines]
    if not rules or len(rules) > CONF['max_ad_rules']: raise ValueError('unexpected core source size')
    return rules

def optimize(rules, full):
    mitm = read_sections(full)['[MITM]']
    line = next(l for l in mitm if l.startswith('hostname'))
    protected = {h.strip()[1:] for h in line.split('=', 1)[1].split(',') if h.strip().startswith('-') and not h.strip().startswith('-*.')}
    shared = {'bytedance.com','byteimg.com','pstatp.com','snssdk.com','qq.com','weixin.qq.com','taobao.com','tmall.com','alicdn.com','jd.com','360buyimg.com','pinduoduo.com','yangkeduo.com','douyin.com','amemv.com','xiaohongshu.com','xhscdn.com','bilibili.com','biliapi.net','amap.com','suning.com','meituan.com','dianping.com','ele.me','baidu.com','163.com'}
    # These are normal app APIs or shared infrastructure, not dedicated ad endpoints.
    shared.update({'api.biliapi.com', 'app.biliapi.com', 'api.biliapi.net', 'app.biliapi.net',
                   'firebaseinstallations.googleapis.com', 'firebaseremoteconfig.googleapis.com',
                   'docer.com', 'iciba.com', 'rumble.com'})
    initial = []; seen = set()
    for l in rules:
        if l in seen: continue
        seen.add(l); f = l.split(','); t = f[0]
        if t in {'DEST-PORT', 'USER-AGENT'}: continue
        if 'DOMAIN-KEYWORD,volc)' in l: continue
        if t in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            d = f[1]
            if d in shared or any(d == p or d.endswith('.' + p) or (t == 'DOMAIN-SUFFIX' and p.endswith('.' + d)) for p in protected): continue
        if t == 'DOMAIN-KEYWORD':
            k = f[1]
            if k in {'m.suning.com','advert','tracker','analytics','analysis','log','ads','ad'} or any(k in p for p in protected): continue
        initial.append(l)
    suffix = {l.split(',')[1] for l in initial if l.startswith('DOMAIN-SUFFIX,')}
    keywords = [l.split(',')[1] for l in initial if l.startswith('DOMAIN-KEYWORD,')]
    kr = re.compile('|'.join(re.escape(k) for k in sorted(keywords, key=len, reverse=True))) if keywords else None
    kept = []; ips = []
    for l in initial:
        f = l.split(','); t = f[0]
        if t in {'DOMAIN','DOMAIN-SUFFIX'}:
            d = f[1]; p = d.split('.'); parents = ['.'.join(p[i:]) for i in range(1,len(p))]
            if any(q in suffix for q in ([d] if t == 'DOMAIN' else []) + parents) or (kr and kr.search(d)): continue
        elif t == 'DOMAIN-KEYWORD':
            if any(k != f[1] and k in f[1] for k in keywords): continue
        elif t in {'IP-CIDR','IP-CIDR6'}:
            ips.append((l, ipaddress.ip_network(f[1]), 'no-resolve' in f)); continue
        kept.append(l)
    ipkeep = []
    for l,n,nr in sorted(ips,key=lambda t:(t[1].version,t[1].prefixlen,str(t[1]))):
        if not any(m.version == n.version and nr2 == nr and n.subnet_of(m) for _,m,nr2 in ipkeep):
            ipkeep.append((l,n,nr)); kept.append(l)
    if not 100 <= len(kept) <= CONF['max_ad_rules']: raise ValueError('core rule count guard failed')
    return kept

def validate_public_contract(full, ad, feature):
    builtins = {'DIRECT', 'REJECT', 'REJECT-DROP', 'REJECT-TINYGIF', 'PROXY'}
    sections = read_sections(full)
    groups = {}
    for row in active(sections['[Proxy Group]']):
        name, value = row.split('=', 1)
        if name.strip() in groups: raise ValueError('duplicate proxy group')
        fields = [f.strip() for f in value.split(',')]
        dependencies = []
        for value in fields[1:]:
            if '=' in value: break
            if value: dependencies.append(value)
        groups[name.strip()] = dependencies
    for name, dependencies in groups.items():
        for dependency in dependencies:
            if dependency not in groups and dependency not in builtins:
                raise ValueError('undefined group dependency: ' + dependency)
    def visit(name, stack):
        if name in stack: raise ValueError('proxy group cycle')
        for dependency in groups[name]:
            if dependency in groups: visit(dependency, stack | {name})
    for name in groups: visit(name, set())
    for text, allowed in ((full, builtins | set(groups)), (ad, builtins), (feature, builtins)):
        parts = read_sections(text)
        rules = active(parts.get('[Rule]', []))
        for row in rules:
            fields = [f.strip() for f in row.split(',')]
            policy = fields[-2] if fields[-1] == 'no-resolve' else fields[-1]
            if policy not in allowed: raise ValueError('undefined routing policy: ' + policy)
        for row in active(parts.get('[Script]', [])):
            if attr(row, 'type') not in {'http-request', 'http-response', 'cron'}:
                raise ValueError('unsupported script type')
            if not attr(row, 'script-path'): raise ValueError('missing script path')
        for row in active(parts.get('[MITM]', [])):
            if row.split('=', 1)[0].strip() in {'ca-p12', 'ca-passphrase'} and row.split('=', 1)[1].strip():
                raise ValueError('private certificate in public configuration')
    rules = active(sections['[Rule]'])
    if not rules[-1].startswith('FINAL,') or sum(r.startswith('FINAL,') for r in rules) != 1:
        raise ValueError('missing or misplaced final policy')


def validate(full, ad, feature):
    validate_public_contract(full, ad, feature)
    adrules = active(read_sections(ad)['[Rule]'])
    if len(adrules) != len(set(adrules)): raise ValueError('duplicate ad rules')
    if not set(adrules) <= set(active(read_sections(full)['[Rule]'])): raise ValueError('full/module ad mismatch')
    for text in (full,feature):
        row = next(l for l in text.splitlines() if l.startswith('member_wxds ='))
        if 'enable=true' not in row: raise ValueError('WeRead must stay enabled')
        rows = active(read_sections(text)['[Script]']); names = [l.split('=',1)[0].strip() for l in rows]
        if len(names) != len(set(names)): raise ValueError('duplicate script names')
    safe = ['www.bytedance.com','m.suning.com','i.weread.qq.com','api.revenuecat.com','mp.weixin.qq.com','api.m.jd.com','edith.xiaohongshu.com','api.bilibili.com','account.wps.cn','pay.weixin.qq.com','api.biliapi.net','app.biliapi.net','api.biliapi.com','app.biliapi.com','firebaseinstallations.googleapis.com','firebaseremoteconfig.googleapis.com','www.iciba.com','www.docer.com','rumble.com']
    for h in safe:
        for l in adrules:
            f=l.split(',');t=f[0]
            if (t=='DOMAIN' and f[1]==h) or (t=='DOMAIN-SUFFIX' and (h==f[1] or h.endswith('.'+f[1]))) or (t=='DOMAIN-KEYWORD' and f[1] in h): raise ValueError('healthy endpoint blocked: '+h)
    return len(adrules)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--offline',action='store_true');parser.add_argument('--bootstrap',action='store_true');args=parser.parse_args()
    profiles = {n:(ROOT/'profiles'/n).read_text() for n in ('full.conf','adblock.sgmodule','enhance.sgmodule')}
    full=profiles['full.conf'];ad=profiles['adblock.sgmodule'];feature=profiles['enhance.sgmodule'];results=[];core=[]
    for source in CONF['core_sources']:
        target=CACHE/'core'/(hashlib.sha256(source['url'].encode()).hexdigest()[:16]+'.list')
        previous=target.read_text() if target.exists() else None
        r=fetch(source['url'],target,args.offline);results.append(r)
        if not target.exists(): raise ValueError('core source has no fallback: '+source['url'])
        try: rules=core_source_rules(target.read_text(),source)
        except Exception:
            if previous is None: target.unlink(missing_ok=True);raise
            target.write_text(previous);rules=core_source_rules(previous,source);r.update(status='fallback',error='invalid new core rules')
        core+=rules
    seed=ROOT/'profiles'/'app-rules.list'
    oldad=active(read_sections(ad)['[Rule]'])
    if args.bootstrap:
        # Only initialize once. A second bootstrap would lose source provenance.
        if seed.exists(): raise ValueError('app seed already initialized')
        corecanon=set(core)
        seed.write_text('\n'.join(l for l in oldad if l not in corecanon)+'\n')
    if not seed.exists(): raise ValueError('run bootstrap first')
    kept=optimize(active(seed.read_text().splitlines())+core,full)
    block='# 自动生成的国内核心广告规则；请编辑profiles，不要修改dist。\n'+'\n'.join(kept)+'\n'
    ad=replace_section(ad,'[Rule]',block)
    oldset=set(oldad); lines=read_sections(full)['[Rule]'];idx=[i for i,l in enumerate(lines) if l.strip() in oldset]
    if not idx: raise ValueError('missing original ad block')
    lo,hi=min(idx),max(idx)
    if any(l.strip() and not l.startswith('#') and l.strip() not in oldset for l in lines[lo:hi+1]):raise ValueError('non-ad routing inside ad block')
    full=replace_section(full,'[Rule]','\n'.join(lines[:lo])+'\n'+block+'\n'+'\n'.join(lines[hi+1:]))
    repository=os.environ.get('GITHUB_REPOSITORY',CONF['owner']+'/'+CONF['repository'])
    raw='https://raw.githubusercontent.com/'+repository+'/'+CONF['branch']+'/'
    refs={}
    for text in (full,ad,feature):
        refs.update(remote_references(text))
    # Copy template references into our repository so upstream refresh produces real content commits.
    def job(item):
        url, (rel, kind) = item
        result = fetch(url, CACHE/rel, args.offline, kind == 'script',
                       None if kind == 'script' else kind)
        result['path'] = 'upstream/' + rel
        # An uncached required dependency cannot produce a public working release.
        if result['status'] == 'unavailable':
            raise ValueError('required dependency unavailable: ' + url)
        return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results += list(pool.map(job, sorted(refs.items())))
    replacements = {url:raw+'upstream/'+rel for url,(rel,kind) in refs.items()}
    for u,new in sorted(replacements.items(),key=lambda t:len(t[0]),reverse=True):
        full=full.replace(u,new);ad=ad.replace(u,new);feature=feature.replace(u,new)
    full=full.replace('# 合并日期：2026-10-05；规则固定快照，远程脚本继续依赖各上游。','# 本文件由GitHub Actions自动构建；核心规则和已缓存引用按计划更新。')
    n=validate(full,ad,feature)
    dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    for name,text in [('shadowrocket.conf',full),('adblock.sgmodule',ad),('enhance.sgmodule',feature)]:
        (dist/name).write_text(text)
    # Stable report: changes only when source bytes/status change, not on every timer tick.
    report={'repository':repository,'ad_rules':n,'references':results,'scope':'核心广告库和实际引用的远程规则/脚本；原生匹配器来自审查后的profiles快照','runtime_tested':False}
    (dist/'update-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    unavailable=sum(r['status']=='unavailable' for r in results)
    print(json.dumps({'ad_rules':n,'remote_references':len(refs),'mirrored':len(replacements),'unavailable':unavailable,'repository':repository},ensure_ascii=False))
if __name__=='__main__':main()
