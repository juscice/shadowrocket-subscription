// Conservative Tieba JSON ad filter. Original implementation, 2026-11-12.
// Binary/protobuf, init/sync, malformed and unfamiliar responses pass through.
// This script never logs requests, cookies, response bodies, or account data.
(function () {
  function pass() { $done({}); }
  try {
    var url = String($request.url || '');
    var match = /^https?:\/\/(?:tiebac|c\.tieba)\.baidu\.com(\/[^?#]*)(?:\?[^#]*)?$/.exec(url);
    if (!match || /[?&]cmd(?:=|&|$)/.test(url)) return pass();
    var pathname = match[1];
    if (!/^\/(?:c\/f\/(?:ad\/getSplashAd|frs\/(?:page|threadlist|generalTabList)|pb\/(?:pic)?page|excellent\/personalized)|tiebaads\/commonbatch)$/.test(pathname)) return pass();
    if ($response.statusCode && Number($response.statusCode) !== 200) return pass();
    var raw = $response.body;
    if (typeof raw !== 'string' || raw.length > 2097152 || !/^\s*\{/.test(raw)) return pass();
    var headers = $response.headers || {};
    for (var header in headers) {
      if (header.toLowerCase() === 'content-type' && /protobuf|octet-stream|image\/|video\//i.test(String(headers[header]))) return pass();
    }
    // JSON.parse/stringify cannot safely preserve unquoted 64-bit thread/cursor IDs.
    var tokenPattern = /"(?:\\.|[^"\\])*"|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
    var token;
    while ((token = tokenPattern.exec(raw)) !== null) {
      if (token[1]) {
        var value = Number(token[1]);
        if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) return pass();
      }
    }
    var payload = JSON.parse(raw);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return pass();
    if (payload.error_code != null && String(payload.error_code) !== '0') return pass();
    var changed = false;
    function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
    function markedAd(value) { return value === true || value === 1 || value === '1'; }
    function clearArray(parent, key) {
      if (object(parent) && Array.isArray(parent[key]) && parent[key].length) { parent[key] = []; changed = true; }
    }
    function clearGoods(list) {
      if (!Array.isArray(list)) return;
      for (var i = 0; i < list.length; i++) clearArray(list[i], 'goods_info');
    }
    function clean(container) {
      if (!object(container)) return;
      if (Array.isArray(container.thread_list)) {
        var kept = container.thread_list.filter(function (item) {
          return !object(item) || (!markedAd(item.is_ad) && !markedAd(item.isAd));
        });
        if (kept.length !== container.thread_list.length) { container.thread_list = kept; changed = true; }
      }
      if (object(container.activityhead) && markedAd(container.activityhead.is_ad)) { container.activityhead = {}; changed = true; }
      clearArray(container, 'ad_list');
      if (object(container.banner_list)) {
        clearGoods(container.banner_list.app);
        clearArray(container.banner_list.pb_banner_ad, 'goods_info');
      }
      if (object(container.forum) && object(container.forum.banner_list)) clearGoods(container.forum.banner_list.app);
      if (/\/frs\/generalTabList$/.test(pathname)) clearGoods(container.app_list);
    }
    clean(payload);
    if (object(payload.data)) clean(payload.data);
    if (pathname === '/tiebaads/commonbatch') clearArray(payload.res, 'ad');
    if (pathname === '/c/f/ad/getSplashAd' && payload.error_code === 0) {
      payload.error_code = 2230209;
      payload.data = null;
      changed = true;
    }
    if (!changed) return pass();
    $done({ body: JSON.stringify(payload) });
  } catch (error) {
    pass();
  }
})();
