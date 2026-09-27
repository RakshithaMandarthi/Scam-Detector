/* Scam Detector - rule engine
 * Pure logic (no DOM), so it runs in the browser and in Node / tests.
 * analyze(text) -> { score, verdict, reasons: [{key, weight, params?}], urls: [{url, host, flagged}] }
 * Reason keys (r.* and u.*) are translated in i18n.js.
 */
(function (root) {
  'use strict';

  var THRESHOLDS = { suspicious: 25, scam: 50 }; // score >= value -> that verdict

  /* ---------- helpers ---------- */
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function isAscii(s) { return /^[\x00-\x7F]+$/.test(s); }
  // Latin words get word boundaries; Hindi/Kannada terms are matched as plain substrings.
  function wordsToSource(words) {
    return words.map(function (w) {
      return isAscii(w) ? '\\b' + escapeRe(w) + '\\b' : escapeRe(w);
    }).join('|');
  }
  function rx(words, extra) {
    return new RegExp([wordsToSource(words), extra].filter(Boolean).join('|'), 'i');
  }

  /* ---------- text rules ---------- */
  var SENSITIVE_ASK = /\b(?:send|share|give|tell|provide|enter|submit|confirm|verify|update|forward)\b[^.!?\n]{0,30}\b(?:otp|pin|cvv|password|passcode|aadhaar|aadhar|pan|kyc|card number|card details|account number|bank details|login details|security code)\b/i;
  var SENSITIVE_WORDS = rx(['kyc', 'verify your account', 'verify your identity', 'net banking', 'card number', 'cvv', 'ओटीपी', 'केवाईसी', 'ಓಟಿಪಿ']);

  var URGENCY = rx(['urgent', 'urgently', 'immediately', 'right now', 'act now', 'pay now', 'verify now', 'update now', 'claim now', 'click now', 'expires', 'expiring', 'expired', 'last chance', 'limited time', 'within 24 hours', 'within 2 hours', 'today only', 'hurry', 'turant', 'तुरंत', 'ತಕ್ಷಣ']);
  var PRIZE = rx(['you have won', 'you won', 'you are a winner', 'winner', 'lottery', 'lucky draw', 'prize', 'jackpot', 'congratulations', 'you have been selected', 'you are selected', 'claim your', 'reward points', 'cashback', 'win rs', 'win a', 'inaam', 'इनाम', 'जीता', 'लॉटरी', 'ಬಹುಮಾನ', 'ಲಾಟರಿ', 'ಗೆದ್ದಿದ್ದೀರಿ']);
  var FREEBIE = rx(['offer', 'bonus', 'discount', 'giveaway', 'special offer', '100% free', 'absolutely free', 'muft', 'मुफ्त', 'मुफ़्त', 'ಉಚಿತ'],
    '\\bfree\\s+(?:gift|iphone|phone|recharge|data|entry|trial|money|coupon|voucher|laptop|tickets?|cash|prize)\\b');
  var MONEY = rx(['send money', 'transfer money', 'processing fee', 'registration fee', 'advance fee', 'pay a fee', 'security deposit', 'gift card', 'bitcoin', 'crypto', 'western union', 'wire transfer', 'pay rs', 'pay inr', 'pay ₹', 'upi pin', 'refund', 'पैसे भेजें', 'पैसे भेजो', 'ಹಣ ಕಳುಹಿಸಿ']);
  var THREAT = rx(['blocked', 'suspended', 'deactivated', 'deactivate', 'locked', 'will be closed', 'legal action', 'arrest', 'arrested', 'police', 'penalty', 'disconnected', 'disconnection', 'court', 'warrant', 'case has been filed', 'ब्लॉक', 'ಬ್ಲಾಕ್']);
  var CLICK = rx(['click', 'tap here', 'tap on', 'download', 'install', 'apk', 'open the link', 'link below', 'follow the link', 'क्लिक', 'ಕ್ಲಿಕ್']);
  var JOB = rx(['work from home', 'earn per day', 'earn daily', 'earn rs', 'earn ₹', 'earn upto', 'guaranteed returns', 'guaranteed profit', 'double your money', 'part-time job', 'part time job', 'online job', 'daily income', 'no experience needed', 'like and earn', 'high returns', 'telegram channel', 'telegram group', 'whatsapp group', 'investment plan', 'crypto trading']);
  var BRAND_WORDS = rx(['bank', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay', 'google pay', 'amazon', 'flipkart', 'paypal', 'netflix', 'microsoft', 'apple', 'income tax', 'rbi', 'customs', 'fedex', 'dhl', 'india post', 'courier', 'parcel', 'delivery', 'airtel', 'jio', 'electricity', 'irctc']);

  function hit(re) { return function (text) { return re.test(text); }; }

  var RULES = [
    { key: 'r.sensitive', weight: 30, test: function (t) { return SENSITIVE_ASK.test(t) || SENSITIVE_WORDS.test(t); } },
    { key: 'r.job',       weight: 30, test: hit(JOB) },
    { key: 'r.prize',     weight: 20, test: hit(PRIZE) },
    { key: 'r.money',     weight: 20, test: hit(MONEY) },
    { key: 'r.threat',    weight: 20, test: hit(THREAT) },
    { key: 'r.urgency',   weight: 15, test: hit(URGENCY) },
    { key: 'r.freebie',   weight: 10, test: hit(FREEBIE) },
    { key: 'r.click',     weight: 10, test: hit(CLICK) },
    { key: 'r.brand',     weight: 10, test: function (t, c) { return c.hasUrl && BRAND_WORDS.test(t); } },
    { key: 'r.shouting',  weight: 5,  test: function (t, c) {
        var bangs = (c.original.match(/!/g) || []).length;
        var letters = c.noUrls.replace(/[^A-Za-z]/g, '');
        var caps = letters.replace(/[^A-Z]/g, '');
        return bangs >= 3 || (letters.length >= 12 && caps.length / letters.length > 0.6);
      } }
  ];
  var NOT_A_CATEGORY = { 'r.brand': 1, 'r.shouting': 1 }; // don't count these toward the "several tactics" bonus

  /* ---------- URL analysis ---------- */
  var TLDS = 'com|net|org|in|co|info|xyz|top|click|link|online|site|club|live|icu|shop|vip|cc|tk|ml|ga|cf|gq|ru|cn|biz|app|page|buzz|work|support|life|store';
  var SHORT_DOMAINS = 'bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|is\\.gd|cutt\\.ly|rb\\.gy|shorturl\\.at|ow\\.ly|tiny\\.cc|t\\.ly';
  var URL_SOURCE =
    '\\b(?:https?:\\/\\/|www\\.)[^\\s<>"\'()]+' +                                   // with scheme or www.
    '|\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d+)?(?:\\/[^\\s<>"\'()]*)?' +              // raw IPv4
    '|\\b(?:' + SHORT_DOMAINS + ')\\/[^\\s<>"\'()]*' +                               // known shorteners
    '|\\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\\.(?:' + TLDS + ')\\b(?:\\/[^\\s<>"\'()]*)?'; // bare domain

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'tiny.cc', 't.ly', 'bl.ink', 's.id'];
  var BAD_TLDS = ['xyz', 'top', 'click', 'link', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'cc', 'work', 'vip'];
  var IP_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  // A host that contains one of these words but is not on the official domain list looks like impersonation.
  var BRANDS = [
    { token: 'sbi',       name: 'SBI',        official: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in', 'sbi.in'] },
    { token: 'onlinesbi', name: 'SBI',        official: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in', 'sbi.in'] },
    { token: 'hdfcbank',  name: 'HDFC Bank',  official: ['hdfcbank.com'] },
    { token: 'hdfc',      name: 'HDFC',       official: ['hdfcbank.com', 'hdfc.com', 'hdfclife.com', 'hdfcergo.com'] },
    { token: 'icicibank', name: 'ICICI Bank', official: ['icicibank.com'] },
    { token: 'icici',     name: 'ICICI',      official: ['icicibank.com', 'icicilombard.com', 'iciciprulife.com'] },
    { token: 'axisbank',  name: 'Axis Bank',  official: ['axisbank.com'] },
    { token: 'paytm',     name: 'Paytm',      official: ['paytm.com', 'paytmbank.com'] },
    { token: 'phonepe',   name: 'PhonePe',    official: ['phonepe.com'] },
    { token: 'amazon',    name: 'Amazon',     official: ['amazon.in', 'amazon.com', 'amazon.co.uk'] },
    { token: 'flipkart',  name: 'Flipkart',   official: ['flipkart.com'] },
    { token: 'paypal',    name: 'PayPal',     official: ['paypal.com', 'paypal.me'] },
    { token: 'netflix',   name: 'Netflix',    official: ['netflix.com'] },
    { token: 'microsoft', name: 'Microsoft',  official: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'] },
    { token: 'apple',     name: 'Apple',      official: ['apple.com', 'icloud.com'] },
    { token: 'google',    name: 'Google',     official: ['google.com', 'google.co.in', 'google.in', 'gstatic.com'] },
    { token: 'facebook',  name: 'Facebook',   official: ['facebook.com', 'fb.com'] },
    { token: 'instagram', name: 'Instagram',  official: ['instagram.com'] },
    { token: 'whatsapp',  name: 'WhatsApp',   official: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
    { token: 'irctc',     name: 'IRCTC',      official: ['irctc.co.in', 'irctc.com'] }
  ];

  function isOfficial(host, domains) {
    return domains.some(function (d) { return host === d || host.slice(-(d.length + 1)) === '.' + d; });
  }

  function findLookalike(host) {
    var tokens = host.split(/[.-]/);
    for (var i = 0; i < BRANDS.length; i++) {
      var b = BRANDS[i];
      if (tokens.indexOf(b.token) !== -1 && !isOfficial(host, b.official)) return b;
    }
    return null;
  }

  function extractUrls(text) {
    var re = new RegExp(URL_SOURCE, 'gi');
    var out = [], seen = {}, m;
    while ((m = re.exec(text))) {
      if (m.index > 0 && text.charAt(m.index - 1) === '@') continue; // domain part of an e-mail address
      var raw = m[0].replace(/[.,;:!?)\]]+$/, '');
      var key = raw.toLowerCase();
      if (!raw || seen[key]) continue;
      seen[key] = true;
      var parsed = parseUrl(raw);
      if (parsed) out.push(parsed);
    }
    return out;
  }

  function parseUrl(raw) {
    var explicit = /^https?:\/\//i.test(raw);
    var full = explicit ? raw : 'http://' + raw;
    var u;
    try { u = new URL(full); } catch (e) { return null; }
    var authority = full.replace(/^https?:\/\//i, '').split(/[\/?#]/)[0];
    return {
      raw: raw,
      host: u.hostname.toLowerCase().replace(/^www\./, ''),
      explicitHttp: explicit && /^http:/i.test(raw),
      hasAt: authority.indexOf('@') !== -1
    };
  }

  function flagUrl(p) {
    var flags = [], host = p.host, labels = host.split('.'), tld = labels[labels.length - 1];
    function add(key, weight, extra) {
      var params = { host: host };
      if (extra) for (var k in extra) params[k] = extra[k];
      flags.push({ key: key, weight: weight, params: params });
    }
    if (p.explicitHttp) add('u.http', 15);
    if (IP_RE.test(host)) add('u.ip', 25);
    if (SHORTENERS.indexOf(host) !== -1) add('u.short', 15);
    if (BAD_TLDS.indexOf(tld) !== -1) add('u.tld', 15);
    if (p.hasAt) add('u.at', 20);
    if (host.indexOf('xn--') !== -1) add('u.puny', 20);
    if (labels.length >= 5 || (host.match(/-/g) || []).length >= 3) add('u.subdomains', 10);
    var look = findLookalike(host);
    if (look) add('u.lookalike', 30, { brand: look.name });
    return flags;
  }

  /* ---------- main ---------- */
  function verdictFor(score) {
    return score >= THRESHOLDS.scam ? 'scam' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'safe';
  }

  function analyze(input) {
    var original = String(input || '').slice(0, 5000);
    var urls = extractUrls(original);
    var noUrls = original.replace(new RegExp(URL_SOURCE, 'gi'), ' ');
    // "Do not share your OTP" is a warning, not a request, so drop those sentences first.
    var cleaned = noUrls.replace(/\b(?:do not|don't|dont|never)\s+(?:share|tell|give|disclose)[^.!?\n]*/gi, ' ');
    var ctx = { original: original, noUrls: noUrls, hasUrl: urls.length > 0 };

    var reasons = [], categories = {}, score = 0, i;

    for (i = 0; i < RULES.length; i++) {
      var rule = RULES[i];
      if (rule.test(cleaned, ctx)) {
        reasons.push({ key: rule.key, weight: rule.weight });
        score += rule.weight;
        if (!NOT_A_CATEGORY[rule.key]) categories[rule.key] = true;
      }
    }

    var urlSummaries = [];
    urls.forEach(function (p) {
      var flags = flagUrl(p);
      flags.forEach(function (f) { reasons.push(f); score += f.weight; });
      if (flags.length) categories.url = true;
      urlSummaries.push({ url: p.raw, host: p.host, flagged: flags.length > 0 });
    });

    if (Object.keys(categories).length >= 3) {
      reasons.push({ key: 'r.combo', weight: 10 });
      score += 10;
    }

    score = Math.min(score, 100);
    reasons.sort(function (a, b) { return b.weight - a.weight; });
    return { score: score, verdict: verdictFor(score), reasons: reasons, urls: urlSummaries };
  }

  var api = { analyze: analyze, verdictFor: verdictFor, extractUrls: extractUrls, THRESHOLDS: THRESHOLDS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Detector = api;
})(typeof window !== 'undefined' ? window : globalThis);
