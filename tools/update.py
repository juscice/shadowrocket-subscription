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

def deduplicate_url_sections(text):
    """Resolve HTTP(S) overlap while preserving actions and exception order."""
    counts = {'removed': 0, 'protocol_overlap_resolved': 0}
    for section in ('[URL Rewrite]', '[Map Local]', '[Body Rewrite]'):
        rows = read_sections(text).get(section)
        if rows is None: continue
        groups = {}
        for i, row in enumerate(rows):
            if not row.strip() or row.lstrip().startswith(('#', '//')): continue
            fields = row.strip().split(None, 2 if section == '[Body Rewrite]' else 1)
            pos = 1 if section == '[Body Rewrite]' else 0
            if len(fields) <= pos + 1: continue
            pattern = fields[pos].replace('\\/', '/')
            if not pattern.startswith(('^https://', '^https?://')): continue
            key = tuple(fields[:pos] + [pattern.replace('^https://', '^https?://', 1)] + fields[pos+1:])
            groups.setdefault(key, []).append((i, fields, pos, pattern))
        removed = set()
        for group in groups.values():
            broad = [entry for entry in group if entry[3].startswith('^https?://')]
            narrow = [entry for entry in group if entry[3].startswith('^https://')]
            if not broad or not narrow or len(group) != 2: continue
            b, n = broad[0], narrow[0]
            if section == '[Body Rewrite]' and b[0] < n[0]: continue
            safe = section != '[Body Rewrite]' and b[0] < n[0]
            if section == '[URL Rewrite]' and n[0] < b[0]:
                action = n[1][-1]
                between = active(rows[n[0]+1:b[0]])
                # An HTTP-only redirect cannot intercept the earlier HTTPS match.
                safe = all(r.split(None, 1)[-1] == action or
                           r.replace('\\/', '/').startswith(('^http://', '^(http://'))
                           for r in between)
            if safe:
                removed.add(n[0]); counts['removed'] += 1
            else:
                # Keep both positions when moving a rule could change priority.
                # Partition HTTPS (earlier) and HTTP (later) instead.
                fields = b[1][:]
                fields[b[2]] = fields[b[2]].replace('https?', 'http', 1)
                rows[b[0]] = ' '.join(fields)
                counts['protocol_overlap_resolved'] += 1
        text = replace_section(text, section, '\n'.join(row for i, row in enumerate(rows) if i not in removed))
    return text, counts

def financial_exclusions(text):
    hosts = []
    for row in read_sections(text).get('[MITM]', []):
        if row.strip().startswith('hostname'):
            hosts += [h.strip() for h in row.split('=', 1)[1].split(',') if h.strip().startswith('-')]
    return set(hosts)

def apply_financial_exclusions(text, exclusions):
    """Keep exclusions on every entry point; remove contradictory positive hosts."""
    import fnmatch
    roots = {h[1:] for h in exclusions if not h.startswith('-*.')}
    def blocked(host):
        return any(host == root or host.endswith('.'+root) or
                   ('*' in host and fnmatch.fnmatchcase(root, host)) for root in roots)
    rows = read_sections(text)['[MITM]']
    for i, row in enumerate(rows):
        if not row.strip().startswith('hostname'): continue
        value = row.split('=', 1)[1].strip()
        append = value.startswith('%APPEND%')
        if append: value = value[len('%APPEND%'):].strip()
        hosts = [h.strip() for h in value.split(',') if h.strip()]
        hosts = [h for h in hosts if h.startswith('-') or not blocked(h)]
        rows[i] = 'hostname = '+('%APPEND% ' if append else '')+','.join(dict.fromkeys(hosts+sorted(exclusions)))
    return replace_section(text, '[MITM]', '\n'.join(rows))

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
    if kind == 'routing':
        rows = active(text.splitlines())
        if not rows or len(rows) > 50000: raise ValueError('invalid routing source size')
        for row in rows: canonical_routing_rule(row)
    elif kind == 'json':
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


def canonical_routing_rule(line):
    """Normalize policy-free source entries without accidentally turning routes into ads."""
    fields = [x.strip() for x in line.split(',')]
    allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
               'IP-ASN', 'USER-AGENT', 'URL-REGEX', 'GEOIP'}
    if len(fields) < 2 or fields[0] not in allowed or not fields[1]:
        raise ValueError('unsupported routing source entry: ' + line)
    kind, target = fields[:2]
    if kind.startswith('DOMAIN'):
        target = target.lower().rstrip('.')
        if not re.fullmatch(r'[a-z0-9_.-]+', target): raise ValueError('invalid routing domain')
    if kind in {'IP-CIDR', 'IP-CIDR6'}:
        network = ipaddress.ip_network(target, strict=False)
        kind = 'IP-CIDR' if network.version == 4 else 'IP-CIDR6'
        return ','.join([kind, str(network), 'no-resolve'])
    return ','.join([kind, target])


def deduplicate_routing(rows):
    # Only fold suffix/network coverage inside the same policy. A precise exception
    # under a DIFFERENT policy must remain and must keep its original precedence.
    rows = list(dict.fromkeys(rows))
    suffixes = {r.split(',')[1] for r in rows if r.startswith('DOMAIN-SUFFIX,')}
    networks = [(r, ipaddress.ip_network(r.split(',')[1])) for r in rows
                if r.startswith(('IP-CIDR,', 'IP-CIDR6,'))]
    result = []
    for row in rows:
        kind, target = row.split(',')[:2]
        if kind in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            parts = target.split('.')
            parents = ['.'.join(parts[i:]) for i in range(1, len(parts))]
            if any(p in suffixes for p in parents + ([target] if kind == 'DOMAIN' else [])):
                continue
        if kind in {'IP-CIDR', 'IP-CIDR6'}:
            net = ipaddress.ip_network(target)
            if any(net != other and net.version == other.version and net.subnet_of(other)
                   for _, other in networks): continue
        result.append(row)
    return result


def build_routing(offline):
    results, lines, counts, seen = [], list(CONF.get('routing_prefix', [])), {}, set()
    for row in lines:
        if row.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'IP-CIDR6,')):
            seen.add(canonical_routing_rule(row))
    for source in CONF.get('routing_sources', []):
        rows = []
        for url in source['urls']:
            target = CACHE/'routing'/(hashlib.sha256(url.encode()).hexdigest()[:20]+'.list')
            result = fetch(url, target, offline, content_kind='routing')
            result['path'] = str(target.relative_to(ROOT)); results.append(result)
            if result['status'] == 'unavailable': raise ValueError('routing source unavailable: ' + url)
            rows += [canonical_routing_rule(r) for r in active(target.read_text().splitlines())]
        if not rows or len(rows) > 50000: raise ValueError('routing source size guard')
        kept = deduplicate_routing(rows)
        # Earlier groups own exact matcher conflicts. Broader routes under another
        # policy remain intentional fallbacks (e.g. push.apple.com before apple.com).
        kept = [r for r in kept if r not in seen]
        seen.update(kept)
        counts[source['name']] = {'input': len(rows), 'kept': len(kept), 'removed': len(rows)-len(kept)}
        lines.append('# '+source['name']+' -> '+source['policy'])
        for row in kept:
            f = row.split(',')
            lines.append(','.join(f[:2]+[source['policy']]+f[2:]))
    return '\n'.join(lines), results, counts


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
    bank_hosts = CONF.get('bank_exact_hosts', [])
    shared_exclusions = financial_exclusions(full) | {'-'+h for h in bank_hosts}
    for domain in CONF.get('bank_direct_suffixes', []):
        shared_exclusions.update({'-'+domain, '-*.'+domain})
    full = apply_financial_exclusions(full, shared_exclusions)
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
    routing, routing_results, routing_counts = build_routing(args.offline)
    results += routing_results
    if CONF.get('routing_sources'):
        pattern = r'# BEGIN GENERATED ROUTING\n.*?# END GENERATED ROUTING'
        full, changed = re.subn(pattern, lambda _: '# BEGIN GENERATED ROUTING\n'+routing+'\n# END GENERATED ROUTING', full, flags=re.S)
        if changed != 1: raise ValueError('missing or repeated generated routing marker')
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
    # Duplicate standalone rule rows use first-match precedence. Do not reorder them.
    seen_rules = set(); unique_rules = []
    for row in read_sections(full)['[Rule]']:
        if row.strip() and not row.lstrip().startswith('#'):
            normalized = ','.join(f.strip() for f in row.split(','))
            if normalized in seen_rules: continue
            seen_rules.add(normalized)
        unique_rules.append(row)
    full = replace_section(full, '[Rule]', '\n'.join(unique_rules))
    # New financial routes must never expand the HTTPS decryption scope.
    exclusions = set()
    for row in routing.splitlines():
        f = row.split(',')
        if len(f) >= 3 and f[2] in {'🏦 汇丰香港', '🏦 香港银行', '📈 券商服务'} and f[0] in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            exclusions.add('-'+f[1])
            if f[0] == 'DOMAIN-SUFFIX': exclusions.add('-*.'+f[1])
    mitm = read_sections(full)['[MITM]']
    for i, row in enumerate(mitm):
        if row.startswith('hostname'):
            hosts = [h.strip() for h in row.split('=', 1)[1].split(',')]
            mitm[i] = 'hostname = '+','.join(dict.fromkeys(hosts+sorted(exclusions)))
    full = replace_section(full, '[MITM]', '\n'.join(mitm))
    shared_exclusions |= financial_exclusions(full)
    full = apply_financial_exclusions(full, shared_exclusions)
    ad = apply_financial_exclusions(ad, shared_exclusions)
    feature = apply_financial_exclusions(feature, shared_exclusions)
    # Known bank app hosts use the current network, before SDK/IP-ASN fallbacks.
    bank_rows = ['DOMAIN,'+h+',DIRECT' for h in bank_hosts]
    bank_rows += ['DOMAIN-SUFFIX,'+d+',DIRECT' for d in CONF.get('bank_direct_suffixes', [])]
    bank_block = '# BEGIN BANK COMPATIBILITY\n'+'\n'.join(bank_rows)+'\n# END BANK COMPATIBILITY'
    full = re.sub(r'# BEGIN BANK COMPATIBILITY\n.*?# END BANK COMPATIBILITY\n?', '', full, flags=re.S)
    full = replace_section(full, '[Rule]', bank_block+'\n'+'\n'.join(read_sections(full)['[Rule]']))
    full, _ = deduplicate_url_sections(full)
    ad, _ = deduplicate_url_sections(ad)
    feature, _ = deduplicate_url_sections(feature)
    n=validate(full,ad,feature)
    dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    for name,text in [('shadowrocket.conf',full),('adblock.sgmodule',ad),('enhance.sgmodule',feature)]:
        (dist/name).write_text(text)
    # Stable report: changes only when source bytes/status change, not on every timer tick.
    report={'repository':repository,'ad_rules':n,'routing_merge':routing_counts,'references':results,'scope':'核心广告库、LingJing分流补充与实际引用的远程规则/脚本；原生匹配器来自审查后的profiles快照','runtime_tested':False}
    (dist/'update-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    unavailable=sum(r['status']=='unavailable' for r in results)
    print(json.dumps({'ad_rules':n,'remote_references':len(refs),'mirrored':len(replacements),'unavailable':unavailable,'repository':repository},ensure_ascii=False))
if __name__=='__main__':main()
