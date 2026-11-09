"""Browser regression tests with a mocked Clash controller and IP services.

Run: .venv/bin/python ipcheck-yh/tests/smoke.py
Uses an installed Playwright browser, or macOS Google Chrome if present.
No real controller/API requests or node changes are made.
"""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
SCRIPT = (HERE.parent / 'clash-ipcheck.user.js').read_text()
SAMPLE = json.loads((HERE / 'teleapi.sample.json').read_text())
OUT = HERE / 'artifacts'
OUT.mkdir(exist_ok=True)

MOCK = r"""
window.db = new Map();
window.GM_getValue = (k, fallback) => window.db.has(k) ? structuredClone(window.db.get(k)) : fallback;
window.GM_setValue = (k, v) => window.db.set(k, structuredClone(v));
window.GM_deleteValue = k => window.db.delete(k);
window.mock = {
 mode: 'rule', calls: [], reportCount: 0, connections: [], next: 0,
 direct: false, wrongChain: false, failReport: false, slow: false, failRestore: false,
 proxies: {
   GLOBAL: {type:'Selector',now:'Group',all:['Group','Auto','B','Broken','DIRECT']},
   Group: {type:'Selector',now:'B',all:['A','B','Broken']},
   Auto: {type:'URLTest',now:'C',fixed:'',all:['C']},
   A: {type:'Shadowsocks'}, B: {type:'VMess'}, C: {type:'Trojan'}, Broken: {type:'VLESS'},
   DIRECT: {type:'Direct'}, REJECT: {type:'Reject'},
   NoRoute: {type:'Trojan'}
 }
};
function activeNode(name='GLOBAL') {
 const p=mock.proxies[name]; return p.all ? activeNode(p.now) : name;
}
window.GM_xmlhttpRequest = options => {
 const u = new URL(options.url);
 const method = options.method || 'GET';
 const payload = options.data ? JSON.parse(options.data) : null;
 const call = {path:u.pathname,method,data:payload,headers:options.headers,host:u.hostname};
 mock.calls.push(call);
 let aborted=false;
 const send = (body,status=200) => {if(!aborted) options.onload({status,responseText:status===204?'':JSON.stringify(body),finalUrl:options.url});};
 const error = () => {if(!aborted) options.onerror();};
 const timer=setTimeout(() => {
  try {
   if(u.hostname==='api.ipify.org') {
     if(mock.direct) { setTimeout(()=>send({ip:'198.247.1.242'}),250); return; }
     const id='probe-'+(++mock.next);
     const name=activeNode();
     mock.connections.push({id,metadata:{host:'api.ipify.org'},start:new Date().toISOString(),chains:[mock.wrongChain?'DIRECT':name,'GLOBAL']});
     setTimeout(()=>send({ip:'198.247.1.242'}),mock.slow ? 12000:280);
   } else if(u.hostname==='ai01.teleapi.top') {
     mock.reportCount++;
     if(mock.failReport) setTimeout(error,50);
     else setTimeout(()=>send(SAMPLE),70);
   } else if(u.pathname==='/version') send({version:'test-mihomo'});
   else if(u.pathname==='/configs') {
     if(method==='PATCH') {
       if(mock.failRestore && payload.mode==='rule') {send({},500);return;}
       mock.mode=payload.mode; send(null,204);
     } else send({mode:mock.mode});
   } else if(u.pathname==='/proxies') send({proxies:mock.proxies});
   else if(u.pathname==='/connections') send({connections:mock.connections});
   else if(u.pathname.startsWith('/connections/')) {
     mock.connections=mock.connections.filter(c=>c.id!==decodeURIComponent(u.pathname.split('/').at(-1)));send(null,204);
   } else if(u.pathname.startsWith('/proxies/')) {
     const name=decodeURIComponent(u.pathname.slice('/proxies/'.length));
     const group=mock.proxies[name];
     if(method==='PUT') {
       if(payload.name==='Broken') {send({},503); return;}
       group.now=payload.name; if(group.type!=='Selector') group.fixed=payload.name;
       send(null,204);
     } else if(method==='DELETE') {group.fixed='';send(null,204);}
     else send(group);
   } else throw Error('Unexpected request '+options.url);
  } catch(e) { window.mockError=String(e); error(); }
 },10);
 return {abort(){aborted=true;clearTimeout(timer);options.onabort();}};
};
"""


def root_value(page, expression):
    return page.evaluate("() => {const r=document.querySelector('#ipcheck-yh-host').shadowRoot;" + expression + "}")


def wait_idle(page):
    page.wait_for_function("() => {const r=document.querySelector('#ipcheck-yh-host').shadowRoot;return !r.querySelector('#load').disabled && !r.querySelector('#status').textContent.includes('正在恢复');}", timeout=25000)


def start(page, selector):
    before = page.evaluate('mock.calls.length')
    page.locator(selector).click()
    page.wait_for_function('(before) => mock.calls.length > before', arg=before)


def fresh(browser):
    page = browser.new_page(viewport={"width": 1440, "height": 1100}, reduced_motion='reduce')
    # A secure loopback origin enables the real Web Locks API. Every network call is mocked.
    page.route('http://127.0.0.1:9097/**', lambda route: route.fulfill(body='<html><body><h1>Clash dashboard fixture</h1></body></html>', content_type='text/html'))
    page.goto('http://127.0.0.1:9097/ui/')
    page.evaluate('window.SAMPLE=' + json.dumps(SAMPLE))
    page.evaluate('(() => {' + MOCK + '\n})()')
    page.evaluate(SCRIPT)
    page.locator('#launch').click()
    page.locator('#secret').fill('test-only-secret')
    page.locator('#load').click()
    wait_idle(page)
    assert page.locator('#rows tr').count() == 5
    return page


def check_restored(page):
    assert page.evaluate('mock.mode') == 'rule'
    assert page.evaluate('mock.proxies.GLOBAL.now') == 'Group'
    assert page.evaluate('mock.proxies.Group.now') == 'B'
    assert page.evaluate('mock.proxies.Auto.fixed') == ''
    assert not page.evaluate("db.has('ipcheck-yh-recovery-v1')")
    assert page.evaluate('window.mockError || null') is None
    # Ensure secrets are never sent to third-party services and all mutation scopes are narrow.
    assert page.evaluate("mock.calls.filter(c=>!['127.0.0.1','localhost'].includes(c.host)).every(c=>!c.headers.Authorization)")
    assert page.evaluate("mock.calls.every(c=>!(c.method==='DELETE' && c.path==='/connections'))")


with sync_playwright() as p:
    chrome = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
    browser = p.chromium.launch(headless=True, **({'executable_path': str(chrome)} if chrome.exists() else {}))
    errors = []

    # Completed reports survive a new page without reconnecting or making requests.
    page = fresh(browser)
    start(page, '[data-run="0"]')
    wait_idle(page)
    saved = page.evaluate('JSON.stringify([...db])')
    assert 'test-only-secret' not in saved
    page.close()
    page = browser.new_page()
    page.route('http://127.0.0.1:9097/**', lambda route: route.fulfill(body='<html><body></body></html>', content_type='text/html'))
    page.goto('http://127.0.0.1:9097/ui/')
    page.evaluate('window.SAMPLE=' + json.dumps(SAMPLE))
    page.evaluate('(() => {' + MOCK + '\n})()')
    page.evaluate('(saved) => { window.db = new Map(JSON.parse(saved)); }', saved)
    page.evaluate(SCRIPT)
    page.locator('#launch').click()
    assert page.locator('#done').inner_text() == '1', 'Saved results must be restored on a new page'
    assert page.locator('#rows > tr[data-node]').count() == 5
    assert page.evaluate('mock.calls.length') == 0
    assert page.locator('#secret').input_value() == ''
    assert page.locator('[data-run="0"]').is_disabled(), 'Saved routes must not authorize mutations before connecting'
    assert '历史记录' in page.locator('#historyStatus').inner_text()
    assert '历史记录' in page.locator('[data-node="0"]').inner_text()
    page.locator('button[data-detail="0"]').last.click()
    assert '完整原始 JSON' in page.locator('#node-detail-0').inner_text()
    page.locator('#region').select_option(label=SAMPLE['derived']['geo']['country'])
    assert page.locator('#rows > tr[data-node]').count() == 1
    page.locator('#region').select_option('')
    page.locator('#secret').fill('test-only-secret')
    page.locator('#load').click()
    wait_idle(page)
    assert page.locator('#done').inner_text() == '1'
    assert page.locator('[data-run="0"]').is_enabled()
    assert page.evaluate('mock.reportCount') == 0, 'Reconnect must not recheck reports'
    start(page, '[data-run="0"]')
    wait_idle(page)
    assert page.evaluate('mock.reportCount') == 1, 'Explicit recheck must request a new report'
    assert '历史记录' not in page.locator('[data-node="0"]').inner_text()
    # Switching subscriptions archives old reports instead of discarding them.
    page.evaluate("mock.proxies.Group.all=['NewNode']; mock.proxies.Group.now='NewNode'; mock.proxies.GLOBAL.all=['Group']; for (const name of ['A','B','C','Broken','NoRoute']) delete mock.proxies[name]; mock.proxies.NewNode={type:'Trojan'};")
    page.locator('#load').click()
    wait_idle(page)
    assert page.locator('#done').inner_text() == '1', 'Subscription switch must retain old reports'
    old_row = page.locator('#rows > tr[data-node]').filter(has=page.get_by_role('button', name='A', exact=True))
    assert '不在当前订阅' in old_row.inner_text()
    assert old_row.locator('[data-run]').is_disabled()
    if old_row.locator('button[data-detail]').last.get_attribute('aria-expanded') != 'true':
        old_row.locator('button[data-detail]').last.click()
    assert '完整原始 JSON' in page.locator('.inline-detail').inner_text()
    assert page.evaluate("db.get('ipcheck-yh-history-v1').results.some(r=>r.name==='A')")
    page.evaluate("mock.proxies.A={type:'Shadowsocks'}; mock.proxies.Group.all.push('A')")
    page.locator('#load').click()
    wait_idle(page)
    old_row = page.locator('#rows > tr[data-node]').filter(has=page.get_by_role('button', name='A', exact=True))
    assert old_row.locator('[data-run]').is_enabled()
    assert '不在当前订阅' not in old_row.inner_text()
    assert page.locator('#done').inner_text() == '1'
    # Clearing reports must never erase a pending controller recovery journal.
    page.evaluate("db.set('ipcheck-yh-recovery-v1', {mode:'rule',groups:[],origin:location.origin,at:Date.now()})")
    page.on('dialog', lambda dialog: dialog.accept())
    page.locator('#clearHistory').click()
    assert page.locator('#done').inner_text() == '0'
    assert page.evaluate("db.has('ipcheck-yh-recovery-v1')")
    assert not page.evaluate("db.has('ipcheck-yh-history-v1')")
    page.close()
    print('PASS history new-page restore, offline details, credential isolation, reconnect, explicit recheck, clear isolation')

    # Sorting is numeric, stable for ties, and always places missing scores last.
    page = fresh(browser)
    assert page.locator('#qualitySort').count() == 1, 'Missing quality sorting control'
    for index, score in [(0, 9), (1, 100), (2, 9)]:
        page.evaluate("([score, country]) => { SAMPLE.derived.coefficient.value=score; SAMPLE.derived.geo.country=country; }", [score, '日本' if index != 1 else '美国'])
        start(page, f'[data-run="{index}"]')
        wait_idle(page)
    def visible_names():
        return page.locator('#rows > tr[data-node] td.name button').all_text_contents()
    assert visible_names() == ['B', 'A', 'C', 'Broken', 'NoRoute']
    page.locator('#qualitySort').click()
    assert visible_names() == ['A', 'C', 'B', 'Broken', 'NoRoute']
    assert page.locator('#qualityHeader').get_attribute('aria-sort') == 'ascending'
    page.locator('#qualitySort').click()
    assert visible_names()[0] == 'B'
    page.locator('#region').select_option('日本')
    assert visible_names() == ['A', 'C']
    page.locator('#search').fill('Trojan')
    assert visible_names() == ['C'], 'Search must include protocol and combine with region'
    page.locator('#search').fill('')
    page.locator('#selectAll').check()
    page.locator('#region').select_option('')
    assert page.locator('[data-select="0"]').is_checked()
    assert page.locator('[data-select="2"]').is_checked()
    assert not page.locator('[data-select="1"]').is_checked(), 'Select all must only affect visible nodes'
    page.locator('#region').select_option('日本')
    before_url = page.url
    before_calls = page.evaluate('mock.calls.length')
    page.locator('button[data-detail="0"]').last.click()
    detail_row = page.locator('#node-detail-0')
    assert detail_row.is_visible()
    assert page.locator('#panel').is_visible()
    assert page.locator('button[data-detail="0"]').last.get_attribute('aria-expanded') == 'true'
    page.locator('#qualitySort').click()
    assert detail_row.is_visible(), 'Sorting must preserve expanded details'
    assert root_value(page, 'return r.querySelector("#node-detail-0").previousElementSibling.dataset.node;') == '0'
    page.locator('button[data-detail="2"]').last.click()
    assert page.locator('#node-detail-2').is_visible()
    page.locator('button[data-detail="0"]').last.click()
    assert page.locator('#node-detail-0').count() == 0
    assert page.locator('#node-detail-2').is_visible()
    assert page.url == before_url and len(page.context.pages) == 1
    assert page.evaluate('mock.calls.length') == before_calls, 'Details must use the existing report'
    page.locator('#search').fill('no matching node')
    assert '没有符合条件' in page.locator('#rows').inner_text()
    page.locator('#search').fill('')
    assert page.locator('#node-detail-2').is_visible()
    page.set_viewport_size({'width':390,'height':844})
    assert root_value(page, 'return r.querySelector("#panel").scrollWidth <= 390;')
    page.close()
    print('PASS numeric sorting, missing scores, region + protocol filtering, visible selection, inline expansion persistence')

    page = fresh(browser)
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.screenshot(path=str(OUT / 'desktop-initial.png'), full_page=True)
    start(page, '#all')
    wait_idle(page)
    assert page.locator('#done').inner_text() == '3', (page.locator('#status').inner_text(), page.locator('#rows').inner_text(), page.evaluate('mock.calls'))
    assert page.locator('#failed').inner_text() == '1'
    assert page.locator('#unique').inner_text() == '1'
    assert page.evaluate('mock.reportCount') == 1
    check_restored(page)
    # A's path must select the nested group before GLOBAL, including Unicode-safe URL handling.
    calls = page.evaluate("mock.calls.filter(c=>c.method==='PUT')")
    assert calls[0]['path'] == '/proxies/Group' and calls[0]['data']['name'] == 'A'
    assert calls[1]['path'] == '/proxies/GLOBAL' and calls[1]['data']['name'] == 'Group'
    assert any(c['path']=='/proxies/Auto' and c['method']=='DELETE' for c in page.evaluate('mock.calls'))
    page.screenshot(path=str(OUT / 'desktop-results.png'), full_page=True)
    page.locator('[data-detail="0"]').first.click()
    assert page.locator('#node-detail-0').is_visible()
    assert page.locator('#panel').is_visible()
    for field in ['Shodan InternetDB', '数据源对比', '注册与路由', '综合黑名单', '邮件黑名单', '完整原始 JSON', '独享倾向（推测）']:
        assert field in page.locator('#node-detail-0').inner_text()
    assert page.locator('#node-detail-0 a').get_attribute('href') == 'https://ai01.teleapi.top/ipcheck/?ip=198.247.1.242'
    page.screenshot(path=str(OUT / 'desktop-detail.png'), full_page=True)
    page.locator('button[data-detail="0"]').last.click()
    with page.expect_download() as download:
        page.locator('#export').click()
    exported = json.loads(Path(download.value.path()).read_text())
    assert len(exported['results']) == 4
    assert 'test-only-secret' not in json.dumps(exported)
    assert root_value(page, 'return getComputedStyle(r.querySelector("td.verdict")).color;') == 'rgb(231, 237, 248)'
    page.set_viewport_size({'width':390,'height':844})
    page.screenshot(path=str(OUT / 'mobile-results.png'), full_page=True)
    assert root_value(page, 'return r.querySelector("#panel").scrollWidth <= 390;')
    page.locator('#close').click()
    assert not page.locator('#panel').is_visible()
    page.locator('#launch').click()
    assert page.locator('#done').inner_text() == '3'
    page.close()
    print('PASS batch, per-IP cache, nested route, automatic group unpin, details, mobile, close/reopen, credential isolation')

    page = fresh(browser)
    page.evaluate('mock.direct=true')
    start(page, '[data-run="0"]')
    wait_idle(page)
    assert page.locator('#done').inner_text() == '0'
    assert '无法在 Clash 连接中确认' in page.locator('#rows').inner_text()
    assert page.evaluate('mock.reportCount') == 0
    check_restored(page)
    page.close()
    print('PASS direct IP rejected and restored')

    page = fresh(browser)
    page.evaluate('mock.wrongChain=true')
    start(page, '[data-run="0"]')
    wait_idle(page)
    assert '未经过目标节点' in page.locator('#rows').inner_text()
    assert page.evaluate('mock.reportCount') == 0
    check_restored(page)
    page.close()
    print('PASS wrong proxy chain rejected')

    page = fresh(browser)
    page.evaluate('delete mock.proxies.Auto.fixed')
    page.locator('#load').click()
    wait_idle(page)
    assert page.locator('[data-run="2"]').is_disabled()
    assert page.locator('[data-run="0"]').is_enabled()
    page.close()
    print('PASS old automatic group without restorable fixed state is excluded')

    page = fresh(browser)
    page.evaluate('mock.failReport=true')
    start(page, '[data-run="0"]')
    wait_idle(page)
    assert page.locator('#failed').inner_text() == '1'
    check_restored(page)
    page.close()
    print('PASS report failure restores configuration')

    page = fresh(browser)
    page.evaluate('mock.slow=true')
    start(page, '#all')
    page.wait_for_function("mock.calls.some(c=>c.host==='api.ipify.org')")
    page.locator('#stop').click()
    wait_idle(page)
    assert '已停止' in page.locator('#status').inner_text()
    check_restored(page)
    page.close()
    print('PASS cancellation aborts probe and restores configuration')

    page = fresh(browser)
    page.evaluate('mock.failRestore=true')
    start(page, '[data-run="0"]')
    wait_idle(page)
    assert page.evaluate("db.has('ipcheck-yh-recovery-v1')")
    assert page.locator('#recovery').is_visible()
    assert page.locator('#all').is_disabled()
    assert '自动恢复未完成' in page.locator('#status').inner_text()
    # Simulate reload by discarding the injected UI, retaining extension storage/controller.
    page.evaluate("document.querySelector('#ipcheck-yh-host').remove();mock.failRestore=false")
    page.evaluate(SCRIPT)
    page.locator('#launch').click()
    page.locator('#secret').fill('test-only-secret')
    assert page.locator('#recovery').is_visible()
    start(page, '#restore')
    wait_idle(page)
    check_restored(page)
    page.close()
    print('PASS failed recovery journal survives reinjection and manual recovery succeeds')

    assert errors == [], errors
    browser.close()
    print('All browser checks passed; screenshots:', OUT)
