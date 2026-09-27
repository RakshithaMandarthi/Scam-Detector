/* Scam Detector - frontend logic
 * Needs: i18n.js (window.I18N) and detector.js (window.Detector), both loaded first.
 * Talks to the Flask API under /api/*.
 */
(function () {
  'use strict';

  var I18N = window.I18N;
  var Detector = window.Detector;

  /* ---------------------------------------------------------------- helpers */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, value);
    } catch (e) { /* storage blocked - ignore */ }
    return null;
  }

  var ICONS = { safe: '✅', suspicious: '⚠️', scam: '🚨' };
  var LOCALES = { en: 'en-IN', kn: 'kn-IN', hi: 'hi-IN' };
  var SAMPLES = {
    safe: 'Hi, are we still meeting for lunch tomorrow?',
    suspicious: 'Limited time offer! Click the link below for a free recharge.',
    scam: 'CONGRATULATIONS! You have won a free iPhone. Click http://claim-iphone.top now to claim your prize',
    phish: 'Your SBI account is suspended. Verify now: http://sbi-kyc-update.xyz/login'
  };

  var state = {
    lang: I18N[store('lang')] ? store('lang') : 'en',
    user: null,
    googleClientId: null,
    lastResult: null,
    history: [],
    stats: null,
    resetToken: null,
    tab: 'analyze'
  };

  /* ------------------------------------------------------------------- i18n */
  function t(key, params) {
    var s = (I18N[state.lang] && I18N[state.lang][key]) || I18N.en[key] || key;
    if (params) s = s.replace(/\{(\w+)\}/g, function (m, k) { return params[k] !== undefined ? params[k] : m; });
    return s;
  }

  function errText(e) {
    var key = 'err.' + (e && e.code);
    return I18N.en[key] ? t(key) : t('err.generic');
  }

  function applyI18n() {
    document.documentElement.lang = state.lang;
    $$('[data-i18n]').forEach(function (n) { n.textContent = t(n.getAttribute('data-i18n')); });
    $$('[data-i18n-placeholder]').forEach(function (n) { n.placeholder = t(n.getAttribute('data-i18n-placeholder')); });
    $$('[data-i18n-aria]').forEach(function (n) { n.setAttribute('aria-label', t(n.getAttribute('data-i18n-aria'))); });
    $$('[data-toggle]').forEach(function (b) {
      var input = document.getElementById(b.getAttribute('data-toggle'));
      b.setAttribute('aria-label', t(input.type === 'password' ? 'aria.show' : 'aria.hide'));
    });
    if (state.user) $('#greeting').textContent = t('app.hello', { name: state.user.username });
    updateStrength();
    updateLiveWarning();
    if (state.lastResult) renderResult(state.lastResult, false);
    renderHistory();
    renderStats();
  }

  function setLang(lang) {
    state.lang = lang;
    store('lang', lang);
    applyI18n();
  }

  /* -------------------------------------------------------------------- api */
  function api(path, options) {
    options = options || {};
    var init = {
      method: options.method || 'GET',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'ScamDetector' }
    };
    if (options.body) init.body = JSON.stringify(options.body);

    return fetch('/api' + path, init).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          if (res.status === 401 && state.user && data.error === 'auth') sessionExpired();
          throw { code: data.error || 'generic', status: res.status };
        }
        return data;
      });
    }, function () {
      throw { code: 'network' };
    });
  }

  /* --------------------------------------------------------------------- ui */
  var toastTimer;
  function toast(msg) {
    var n = $('#toast');
    n.textContent = msg;
    n.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { n.classList.remove('show'); }, 3200);
  }

  function setMsg(node, text, kind) {
    node.textContent = text || '';
    node.className = 'msg' + (kind ? ' ' + kind : '');
  }

  function busy(btn, on) {
    btn.disabled = on;
    btn.classList.toggle('busy', on);
  }

  function showPanel(name, focus) {
    $$('.panel').forEach(function (p) { p.classList.toggle('hidden', p.id !== 'panel-' + name); });
    $$('.msg').forEach(function (m) { setMsg(m, ''); });
    if (focus) {
      var first = $('#panel-' + name + ' input:not([type=checkbox])');
      if (first) first.focus({ preventScroll: true });
    }
  }

  function showView(name) {
    $('#auth-view').classList.toggle('hidden', name !== 'auth');
    $('#app-view').classList.toggle('hidden', name !== 'app');
    $('#logoutBtn').classList.toggle('hidden', name !== 'app');
    window.scrollTo(0, 0);
  }

  var EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  var USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
  function passwordOk(p) { return p.length >= 8 && /[A-Za-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p); }

  /* ------------------------------------------------------------------- auth */
  function onLoggedIn(user) {
    state.user = user;
    $('#greeting').textContent = t('app.hello', { name: user.username });
    $$('#auth-view input').forEach(function (i) { if (i.type !== 'checkbox') i.value = ''; });
    updateStrength();
    showView('app');
    setTab('analyze');
  }

  function resetAppState() {
    state.user = null;
    state.lastResult = null;
    state.history = [];
    state.stats = null;
    $('#message').value = '';
    $('#result').classList.add('hidden');
    $('#liveWarn').textContent = '';
    setMsg($('#analyzeMsg'), '');
  }

  function showLogin() {
    resetAppState();
    showView('auth');
    showPanel('login');
  }

  function sessionExpired() {
    showLogin();
    setMsg($('#loginMsg'), t('err.auth'), 'error');
  }

  function bindAuth() {
    // switch between panels
    $$('[data-go]').forEach(function (b) {
      b.addEventListener('click', function () { showPanel(b.getAttribute('data-go'), true); });
    });

    // show / hide password
    $$('[data-toggle]').forEach(function (b) {
      b.addEventListener('click', function () {
        var input = document.getElementById(b.getAttribute('data-toggle'));
        var show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        b.textContent = show ? '🙈' : '👁️';
        b.setAttribute('aria-label', t(show ? 'aria.hide' : 'aria.show'));
      });
    });

    // login
    $('#loginForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var msg = $('#loginMsg'), btn = e.target.querySelector('[type=submit]');
      var identifier = $('#loginId').value.trim(), password = $('#loginPass').value;
      if (!identifier || !password) return setMsg(msg, t('err.required'), 'error');
      setMsg(msg, '');
      busy(btn, true);
      api('/login', { method: 'POST', body: { identifier: identifier, password: password, remember: $('#remember').checked } })
        .then(function (d) { onLoggedIn(d.user); })
        .catch(function (err) { setMsg(msg, errText(err), 'error'); })
        .then(function () { busy(btn, false); });
    });

    // register
    $('#registerForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var msg = $('#registerMsg'), btn = e.target.querySelector('[type=submit]');
      var username = $('#regUser').value.trim(), email = $('#regEmail').value.trim();
      var pass = $('#regPass').value, confirm = $('#regConfirm').value;
      if (!username || !email || !pass || !confirm) return setMsg(msg, t('err.required'), 'error');
      if (!USERNAME_RE.test(username)) return setMsg(msg, t('err.username'), 'error');
      if (!EMAIL_RE.test(email)) return setMsg(msg, t('err.email'), 'error');
      if (!passwordOk(pass)) return setMsg(msg, t('err.weak'), 'error');
      if (pass !== confirm) return setMsg(msg, t('err.mismatch'), 'error');
      setMsg(msg, '');
      busy(btn, true);
      api('/register', { method: 'POST', body: { username: username, email: email, password: pass } })
        .then(function (d) { onLoggedIn(d.user); })
        .catch(function (err) { setMsg(msg, errText(err), 'error'); })
        .then(function () { busy(btn, false); });
    });
    $('#regPass').addEventListener('input', updateStrength);

    // forgot password
    $('#forgotForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var msg = $('#forgotMsg'), btn = e.target.querySelector('[type=submit]');
      var email = $('#forgotEmail').value.trim();
      if (!EMAIL_RE.test(email)) return setMsg(msg, t('err.email'), 'error');
      busy(btn, true);
      api('/forgot-password', { method: 'POST', body: { email: email } })
        .then(function () { setMsg(msg, t('forgot.sent'), 'success'); })
        .catch(function (err) { setMsg(msg, errText(err), 'error'); })
        .then(function () { busy(btn, false); });
    });

    // reset password
    $('#resetForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var msg = $('#resetMsg'), btn = e.target.querySelector('[type=submit]');
      var pass = $('#resetPass').value, confirm = $('#resetConfirm').value;
      if (!pass || !confirm) return setMsg(msg, t('err.required'), 'error');
      if (!passwordOk(pass)) return setMsg(msg, t('err.weak'), 'error');
      if (pass !== confirm) return setMsg(msg, t('err.mismatch'), 'error');
      busy(btn, true);
      api('/reset-password', { method: 'POST', body: { token: state.resetToken, password: pass } })
        .then(function () {
          state.resetToken = null;
          history.replaceState(null, '', location.pathname);
          $('#resetPass').value = '';
          $('#resetConfirm').value = '';
          showPanel('login');
          setMsg($('#loginMsg'), t('reset.done'), 'success');
        })
        .catch(function (err) { setMsg(msg, errText(err), 'error'); })
        .then(function () { busy(btn, false); });
    });

    // logout
    $('#logoutBtn').addEventListener('click', function () {
      api('/logout', { method: 'POST' }).catch(function () {}).then(showLogin);
    });

    // Google fallback button (shown only when Google sign-in is not configured)
    $('#googleFallback').addEventListener('click', function () { toast(t('err.google')); });
  }

  /* password strength meter */
  function updateStrength() {
    var p = $('#regPass').value, bar = $('#strengthBar'), label = $('#strengthLabel');
    if (!p) { bar.style.width = '0'; label.textContent = ''; return; }
    var points = 0;
    if (p.length >= 8) points++;
    if (p.length >= 12) points++;
    if (/[a-z]/.test(p) && /[A-Z]/.test(p)) points++;
    if (/\d/.test(p)) points++;
    if (/[^A-Za-z0-9]/.test(p)) points++;
    var level = !passwordOk(p) || points <= 2 ? 'weak' : points === 3 ? 'fair' : 'strong';
    var look = { weak: ['33%', '#ff6b6b'], fair: ['66%', '#ffb74d'], strong: ['100%', '#69f0ae'] }[level];
    bar.style.width = look[0];
    bar.style.background = look[1];
    label.textContent = t('strength.' + level) + ' ·';
  }

  /* Google sign-in (Google Identity Services) */
  function initGoogle() {
    if (!state.googleClientId || !(window.google && google.accounts && google.accounts.id)) return;
    google.accounts.id.initialize({
      client_id: state.googleClientId,
      callback: function (resp) {
        api('/auth/google', { method: 'POST', body: { credential: resp.credential } })
          .then(function (d) { onLoggedIn(d.user); })
          .catch(function (err) { setMsg($('#loginMsg'), errText(err), 'error'); });
      }
    });
    google.accounts.id.renderButton($('#googleSlot'), {
      theme: 'filled_black', size: 'large', shape: 'pill', text: 'continue_with',
      width: Math.max(200, Math.min(320, window.innerWidth - 90))
    });
    $('#googleFallback').classList.add('hidden');
  }
  window.initGoogle = initGoogle;

  /* --------------------------------------------------------------- analyzer */
  function updateLiveWarning() {
    var text = $('#message').value, node = $('#liveWarn');
    if (!text.trim()) { node.textContent = ''; return; }
    var r = Detector.analyze(text);
    var badLink = r.reasons.some(function (x) { return x.key.indexOf('u.') === 0; });
    node.textContent = badLink ? t('warn.link') : r.score >= Detector.THRESHOLDS.suspicious ? t('warn.words') : '';
  }

  var gaugeFrame;
  function setGauge(score, animate) {
    var gauge = $('#gauge'), value = $('#gaugeValue');
    cancelAnimationFrame(gaugeFrame);
    if (!animate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      gauge.style.setProperty('--pct', score);
      value.textContent = score + '%';
      return;
    }
    var start = performance.now(), duration = 700;
    (function tick(now) {
      var p = Math.min((now - start) / duration, 1);
      var cur = Math.round(score * (1 - Math.pow(1 - p, 3)));
      gauge.style.setProperty('--pct', cur);
      value.textContent = cur + '%';
      if (p < 1) gaugeFrame = requestAnimationFrame(tick);
    })(start);
  }

  function reasonText(r) { return t(r.key, r.params); }

  function fillReasons(list, reasons) {
    list.replaceChildren();
    if (!reasons.length) {
      list.appendChild(el('li', 'none', t('reasons.none')));
      return;
    }
    reasons.forEach(function (r) {
      var li = el('li');
      li.appendChild(el('span', '', reasonText(r)));
      li.appendChild(el('span', 'weight', '+' + r.weight));
      list.appendChild(li);
    });
  }

  function renderResult(res, animate) {
    var box = $('#result');
    box.classList.remove('hidden', 'v-safe', 'v-suspicious', 'v-scam');
    box.classList.add('v-' + res.verdict);
    $('#verdictIcon').textContent = ICONS[res.verdict];
    $('#verdictLabel').textContent = t('verdict.' + res.verdict);
    $('#advice').textContent = t('advice.' + res.verdict);
    setGauge(res.score, animate);
    fillReasons($('#reasonList'), res.reasons);

    var urlList = $('#urlList');
    urlList.replaceChildren();
    res.urls.forEach(function (u) {
      urlList.appendChild(el('li', '', (u.flagged ? '⚠️ ' : '✅ ') + u.url));
    });
    $('#urlBlock').classList.toggle('hidden', !res.urls.length);
  }

  function analyze() {
    var text = $('#message').value, msg = $('#analyzeMsg');
    if (!text.trim()) {
      $('#result').classList.add('hidden');
      state.lastResult = null;
      return setMsg(msg, t('err.empty'), 'error');
    }
    setMsg(msg, '');
    var res = Detector.analyze(text);
    state.lastResult = res;
    renderResult(res, true);

    // save to history; the result is already on screen, so a failure only shows a toast
    api('/analyses', { method: 'POST', body: { message: text, score: res.score, verdict: res.verdict, reasons: res.reasons } })
      .catch(function (err) { if (err.code !== 'auth') toast(errText(err)); });
  }

  function bindAnalyzer() {
    var timer;
    $('#message').addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(updateLiveWarning, 150);
    });
    $('#analyzeBtn').addEventListener('click', analyze);
    $('#clearBtn').addEventListener('click', function () {
      $('#message').value = '';
      $('#liveWarn').textContent = '';
      $('#result').classList.add('hidden');
      state.lastResult = null;
      setMsg($('#analyzeMsg'), '');
      $('#message').focus();
    });
    $$('[data-sample]').forEach(function (b) {
      b.addEventListener('click', function () {
        $('#message').value = SAMPLES[b.getAttribute('data-sample')];
        updateLiveWarning();
        $('#message').focus();
      });
    });
  }

  /* -------------------------------------------------------- tabs / history */
  function setTab(name) {
    state.tab = name;
    $$('.tab-btn').forEach(function (b) {
      var on = b.getAttribute('data-tab') === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    ['analyze', 'history', 'dashboard'].forEach(function (n) {
      $('#tab-' + n).classList.toggle('hidden', n !== name);
    });
    if (name === 'history') loadHistory();
    if (name === 'dashboard') loadStats();
  }

  function fmtDate(iso) {
    try {
      return new Date(iso).toLocaleString(LOCALES[state.lang], { dateStyle: 'medium', timeStyle: 'short' });
    } catch (e) { return iso; }
  }

  function loadHistory() {
    api('/history').then(function (d) { state.history = d.items; renderHistory(); })
      .catch(function (err) { if (err.code !== 'auth') toast(errText(err)); });
  }

  function renderHistory() {
    var list = $('#historyList');
    list.replaceChildren();
    $('#historyEmpty').classList.toggle('hidden', state.history.length > 0);
    $('#clearHistory').classList.toggle('hidden', state.history.length === 0);

    state.history.forEach(function (item) {
      var d = el('details', 'hist v-' + item.verdict);
      var s = el('summary');
      var top = el('div', 'hist-top');
      top.appendChild(el('span', 'badge', ICONS[item.verdict] + ' ' + t('verdict.' + item.verdict)));
      top.appendChild(el('span', '', item.score + '%'));
      top.appendChild(el('time', 'hist-date', fmtDate(item.created_at)));
      s.appendChild(top);
      s.appendChild(el('span', 'hist-msg', item.message));
      d.appendChild(s);

      var body = el('div', 'hist-body');
      body.appendChild(el('p', 'hist-full', item.message));
      var ul = el('ul', 'reasons');
      fillReasons(ul, item.reasons);
      body.appendChild(ul);
      var del = el('button', 'btn btn-ghost btn-sm', t('history.delete'));
      del.type = 'button';
      del.addEventListener('click', function () {
        api('/history/' + item.id, { method: 'DELETE' }).then(loadHistory)
          .catch(function (err) { toast(errText(err)); });
      });
      body.appendChild(del);
      d.appendChild(body);
      list.appendChild(d);
    });
  }

  function loadStats() {
    api('/stats').then(function (d) { state.stats = d; renderStats(); })
      .catch(function (err) { if (err.code !== 'auth') toast(errText(err)); });
  }

  function renderStats() {
    var s = state.stats;
    if (!s) return;
    $('#statTotal').textContent = s.total;
    $('#statAvg').textContent = s.avg_score + '%';
    ['safe', 'suspicious', 'scam'].forEach(function (v) {
      var count = (s.by_verdict && s.by_verdict[v]) || 0;
      var pct = s.total ? Math.round(count / s.total * 100) : 0;
      $('#bar-' + v).style.width = pct + '%';
      $('#count-' + v).textContent = count + ' (' + pct + '%)';
    });
  }

  function bindTabs() {
    $$('.tab-btn').forEach(function (b) {
      b.addEventListener('click', function () { setTab(b.getAttribute('data-tab')); });
    });
    $('#clearHistory').addEventListener('click', function () {
      if (!window.confirm(t('history.confirm'))) return;
      api('/history', { method: 'DELETE' }).then(loadHistory)
        .catch(function (err) { toast(errText(err)); });
    });
  }

  /* ------------------------------------------------------------------- init */
  function init() {
    $('#lang').value = state.lang;
    $('#lang').addEventListener('change', function (e) { setLang(e.target.value); });
    bindAuth();
    bindAnalyzer();
    bindTabs();
    applyI18n();

    var token = new URLSearchParams(location.search).get('reset');

    api('/config').then(function (cfg) {
      state.googleClientId = cfg.google_client_id || null;
      if (window.__gisReady) initGoogle();
    }).catch(function () {});

    api('/me').then(function (d) {
      if (d.user) return onLoggedIn(d.user);
      if (token) { state.resetToken = token; showPanel('reset'); } else showPanel('login');
    }).catch(function (err) {
      showPanel('login');
      setMsg($('#loginMsg'), errText(err), 'error');
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
