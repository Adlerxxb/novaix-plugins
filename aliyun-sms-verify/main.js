// 阿里云短信认证服务 v1.0.0 | 白猫云
// 个人认证即可使用的短信验证码服务，无需企业资质。
// Compatible with ES5.1 / Goja runtime

var _codes = {};

// Base64 alphabet
var _b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// RFC 3986 percent-encode
function percentEncode(str) {
    if (str === null || str === undefined) return '';
    return encodeURIComponent(String(str))
        .replace(/!/g, '%21')
        .replace(/'/g, '%27')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29')
        .replace(/\*/g, '%2A');
}

// Hex string → Base64 string (bypasses Goja's UTF-8 String.fromCharCode issue)
function hexToBase64(hex) {
    var result = '';
    for (var i = 0; i < hex.length; i += 6) {
        var chunk = hex.substr(i, 6);
        while (chunk.length < 6) { chunk += '0'; }
        var b0 = parseInt(chunk.substr(0, 2), 16);
        var b1 = parseInt(chunk.substr(2, 2), 16);
        var b2 = parseInt(chunk.substr(4, 2), 16);
        result += _b64.charAt((b0 >> 2) & 0x3F);
        result += _b64.charAt(((b0 << 4) | (b1 >> 4)) & 0x3F);
        result += _b64.charAt(((b1 << 2) | (b2 >> 6)) & 0x3F);
        result += _b64.charAt(b2 & 0x3F);
    }
    var dataBytes = hex.length / 2;
    var mod = dataBytes % 3;
    if (mod === 1) { result = result.substr(0, result.length - 2) + '=='; }
    else if (mod === 2) { result = result.substr(0, result.length - 1) + '='; }
    return result;
}

function getTimestamp() {
    var d = new Date();
    var mm = d.getUTCMonth() + 1;
    var dd = d.getUTCDate();
    var hh = d.getUTCHours();
    var mi = d.getUTCMinutes();
    var ss = d.getUTCSeconds();
    return d.getUTCFullYear() + '-' +
        (mm < 10 ? '0' : '') + mm + '-' +
        (dd < 10 ? '0' : '') + dd + 'T' +
        (hh < 10 ? '0' : '') + hh + ':' +
        (mi < 10 ? '0' : '') + mi + ':' +
        (ss < 10 ? '0' : '') + ss + 'Z';
}

function generateNonce() {
    return '' + new Date().getTime() + '' + Math.floor(Math.random() * 1000000);
}

function isValidPhone(phone) {
    return /^1[3-9]\d{9}$/.test(phone);
}

function cleanupExpiredCodes() {
    var now = new Date().getTime();
    for (var phone in _codes) {
        if (_codes.hasOwnProperty(phone) && _codes[phone].expiry < now) {
            delete _codes[phone];
        }
    }
}

// ---- Alibaba Cloud API Signature V1 (HMAC-SHA256) ----

function callApi(action, apiParams) {
    var allParams = {
        'Action': action,
        'Version': '2017-05-25',
        'Format': 'JSON',
        'Timestamp': getTimestamp(),
        'SignatureMethod': 'HMAC-SHA256',
        'SignatureVersion': '1.0',
        'SignatureNonce': generateNonce(),
        'AccessKeyId': config.access_key_id
    };

    for (var k in apiParams) {
        if (apiParams.hasOwnProperty(k)) {
            allParams[k] = apiParams[k];
        }
    }

    var sortedKeys = [];
    for (var mk in allParams) {
        if (allParams.hasOwnProperty(mk)) { sortedKeys.push(mk); }
    }
    sortedKeys.sort();

    var parts = [];
    for (var i = 0; i < sortedKeys.length; i++) {
        var key = sortedKeys[i];
        parts.push(percentEncode(key) + '=' + percentEncode(allParams[key]));
    }
    var canonicalQuery = parts.join('&');

    var stringToSign = 'GET&' + percentEncode('/') + '&' + percentEncode(canonicalQuery);

    var signingKey = config.access_key_secret + '&';
    var hexSig = crypto.hmacSHA256(signingKey, stringToSign);
    var signature = hexToBase64(hexSig);

    var finalUrl = 'https://dypnsapi.aliyuncs.com/?' +
        canonicalQuery + '&Signature=' + percentEncode(signature);

    log.info('[aliyun-sms] Calling ' + action + ' for ' + (apiParams.PhoneNumber || ''));

    var resp = http.request('GET', finalUrl, { timeout: 30 });

    if (!resp || !resp.body) {
        log.error('[aliyun-sms] Empty response from ' + action);
        return { Code: 'NetworkError', Message: 'Empty response' };
    }

    var result;
    try {
        result = JSON.parse(resp.body);
    } catch (e) {
        log.error('[aliyun-sms] JSON parse error from ' + action);
        return { Code: 'ParseError', Message: 'Invalid JSON' };
    }

    if (result.Code && result.Code !== 'OK') {
        log.warn('[aliyun-sms] API error: ' + result.Code + ' - ' + (result.Message || ''));
    }

    return result;
}

// ---- send: Novaix sms type required function ----

function send(phone, params) {
    if (!phone || !isValidPhone(phone)) {
        throw new Error('手机号格式错误');
    }

    cleanupExpiredCodes();

    // Build template params: code from Novaix + extra vars from config
    var templateObj = {};
    var code = (params && params.code) ? params.code : '';
    templateObj['code'] = code;

    // Merge extra template variables from config (e.g. min=5)
    if (config.template_vars) {
        var extra = config.template_vars;
        if (typeof extra === 'string') {
            try { extra = JSON.parse(extra); } catch (e) { extra = {}; }
        }
        for (var tk in extra) {
            if (extra.hasOwnProperty(tk) && tk !== 'code') {
                // Try to convert numeric strings to numbers
                var val = extra[tk];
                if (/^\d+$/.test(val)) {
                    templateObj[tk] = parseInt(val, 10);
                } else {
                    templateObj[tk] = val;
                }
            }
        }
    }

    var templateParam = JSON.stringify(templateObj);
    log.info('[aliyun-sms] TemplateParam=' + templateParam);

    var apiParams = {
        'PhoneNumber': phone,
        'SignName': config.sign_name,
        'TemplateCode': config.template_code,
        'TemplateParam': templateParam,
        'CountryCode': '86'
    };

    if (config.code_length) apiParams['CodeLength'] = config.code_length;
    if (config.valid_time) apiParams['ValidTime'] = config.valid_time;
    if (config.code_type) apiParams['CodeType'] = config.code_type;
    if (config.scheme_name) apiParams['SchemeName'] = config.scheme_name;

    var result = callApi('SendSmsVerifyCode', apiParams);

    if (result.Code === 'OK' && result.Success) {
        log.info('[aliyun-sms] SMS sent to ' + phone);
        return;
    }

    var errMsg = (result.Code || 'Unknown') + ': ' + (result.Message || '发送失败');
    log.error('[aliyun-sms] Send failed to ' + phone + ': ' + result.Code);
    throw new Error(errMsg);
}

// ---- sendVerificationCode: native Alibaba Cloud auto-generate flow ----

function sendVerificationCode(phone) {
    if (!phone || !isValidPhone(phone)) {
        return { success: false, error: '手机号格式错误' };
    }

    cleanupExpiredCodes();

    var templateVars = { 'code': '##code##' };

    var apiParams = {
        'PhoneNumber': phone,
        'SignName': config.sign_name,
        'TemplateCode': config.template_code,
        'TemplateParam': JSON.stringify(templateVars),
        'CountryCode': '86'
    };

    if (config.code_length) apiParams['CodeLength'] = config.code_length;
    if (config.valid_time) apiParams['ValidTime'] = config.valid_time;
    if (config.code_type) apiParams['CodeType'] = config.code_type;
    if (config.scheme_name) apiParams['SchemeName'] = config.scheme_name;

    var result = callApi('SendSmsVerifyCode', apiParams);

    if (result.Code === 'OK' && result.Success && result.Model) {
        var code = result.Model.VerifyCode;
        var expireSec = parseInt(config.valid_time, 10) || 300;
        _codes[phone] = {
            code: code,
            expiry: new Date().getTime() + expireSec * 1000
        };
        log.info('[aliyun-sms] Code sent to ' + phone);
        return { success: true, code: code, bizId: result.Model.BizId };
    }

    var errMsg = (result.Code || 'Unknown') + ': ' + (result.Message || '发送失败');
    log.error('[aliyun-sms] Send code failed to ' + phone + ': ' + result.Code);
    return { success: false, error: errMsg };
}

// ---- verifyCode: check code via Alibaba Cloud API ----

function verifyCode(phone, code) {
    if (!phone || !isValidPhone(phone)) {
        return { success: false, verified: false, error: '手机号格式错误' };
    }
    if (!code || !/^\d{4,8}$/.test(code)) {
        return { success: false, verified: false, error: '验证码格式错误' };
    }

    cleanupExpiredCodes();

    var apiParams = {
        'PhoneNumber': phone,
        'VerifyCode': code,
        'CountryCode': '86'
    };

    if (config.scheme_name) apiParams['SchemeName'] = config.scheme_name;

    var result = callApi('CheckSmsVerifyCode', apiParams);

    if (result.Code === 'OK' && result.Success && result.Model) {
        var pass = result.Model.VerifyResult === 'PASS';
        if (pass) {
            delete _codes[phone];
            log.info('[aliyun-sms] Verified OK: ' + phone);
        } else {
            log.warn('[aliyun-sms] Verify failed: ' + phone);
        }
        return { success: true, verified: pass };
    }

    var errMsg = (result.Code || 'Unknown') + ': ' + (result.Message || '验证失败');
    log.error('[aliyun-sms] Verify error for ' + phone + ': ' + result.Code);
    return { success: false, verified: false, error: errMsg };
}
