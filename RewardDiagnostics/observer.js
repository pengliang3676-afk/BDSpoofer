/* Passive observer for the activity eligibility request. No business overrides. */
(function () {
    'use strict';
    var marker = '__bdsRewardDiagnostics020';
    var handler = 'bds_reward_diag_020';
    var endpoint = '/incentive/uanti';
    var maxBody = 65536;
    var maxRequests = 128;
    var hop = Object.prototype.hasOwnProperty;
    function baiduHost(host) {
        return host === 'baidu.com' || host.endsWith('.baidu.com');
    }
    if (!baiduHost(location.hostname) || window[marker]) return;
    var sink = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers[handler];
    if (!sink || typeof sink.postMessage !== 'function' || !window.XMLHttpRequest) return;
    var proto = window.XMLHttpRequest.prototype;
    var originalOpen = proto.open;
    var originalSend = proto.send;
    var addEvent = proto.addEventListener;
    var removeEvent = proto.removeEventListener;
    var records = new WeakMap();
    var sequence = 0;
    function emit(value) {
        try { sink.postMessage(value); } catch (_) { /* Diagnostics must not affect requests. */ }
    }
    function target(value) {
        // Do not invoke an application object's custom string conversion a second time.
        if (typeof value !== 'string') return false;
        try {
            var parsed = new URL(value, location.href);
            return parsed.protocol === 'https:' && baiduHost(parsed.hostname) && parsed.pathname === endpoint;
        } catch (_) { return false; }
    }
    function kind(value) {
        return value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    }
    function parameterSummary(url) {
        var values = new URL(url, location.href).searchParams.getAll('zid');
        return {
            security_param_present: values.length > 0,
            security_param_nonempty: values.some(function (v) { return v.trim().length > 0; }),
            security_param_placeholder: values.some(function (v) { return /^(null|undefined)$/i.test(v.trim()); }),
            security_param_count: Math.min(values.length, 10)
        };
    }
    function reasonSummary(value) {
        var result = {};
        var remaining = 256;
        var fields = ['reasonCode', 'reason_code', 'riskCode', 'risk_code', 'subErrno', 'sub_errno',
            'reason', 'riskMessage', 'message', 'errmsg', 'msg', 'tips'];
        [['data', value.data], ['root', value]].forEach(function (scope) {
            if (!scope[1] || typeof scope[1] !== 'object' || Array.isArray(scope[1])) return;
            fields.forEach(function (key) {
                if (Object.keys(result).length >= 8 || !hop.call(scope[1], key)) return;
                var v = scope[1][key], name = scope[0] + '.' + key;
                if (typeof v === 'number' && Number.isFinite(v)) result[name] = v;
                else if (typeof v === 'string' && remaining > 0) {
                    // Keep short explanations, redact likely identifiers and credential assignments.
                    var clean = v.slice(0, 4096)
                        .replace(/(?:https?:\/\/|www\.)[^\s]+/gi, '[redacted]')
                        .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[redacted]')
                        .replace(/\b(?:BDUSS|Cookie|token|authorization|bearer|zid|cuid|uid|idfa|idfv|utdid)\s*[:=]\s*\S+/gi, '[redacted]')
                        .replace(/[A-Za-z0-9_+\/=.%:-]{16,}/g, '[redacted]')
                        .replace(/\d{6,}/g, '[redacted]')
                        .replace(/[\x00-\x1f\x7f]/g, ' ')
                        .slice(0, Math.min(128, remaining));
                    result[name] = clean;
                    remaining -= clean.length;
                }
            });
        });
        return result;
    }
    function businessSummary(value) {
        var result = { json_state: 'valid', root_type: kind(value) };
        if (!value || typeof value !== 'object' || Array.isArray(value)) return result;
        result.business_code_present = hop.call(value, 'errno');
        if (result.business_code_present) {
            var code = value.errno;
            result.business_code_type = kind(code);
            result.business_code_is_number_zero = code === 0;
            if (typeof code === 'number' && Number.isFinite(code)) result.business_code = code;
            else if (typeof code === 'string' && /^-?\d{1,10}$/.test(code)) result.business_code = code;
        }
        var data = value.data;
        result.data_type = kind(data);
        result.is_safe_present = !!data && typeof data === 'object' && hop.call(data, 'isSafe');
        if (result.is_safe_present) {
            var safe = data.isSafe;
            result.is_safe_type = kind(safe);
            result.is_safe_truthy = !!safe;
            if (typeof safe === 'boolean' || (typeof safe === 'number' && Number.isFinite(safe))) {
                result.is_safe_value = safe;
            } else if (typeof safe === 'string' && ['', '0', '1', 'true', 'false'].includes(safe)) {
                result.is_safe_value = safe;
            }
        }
        result.reason_fields = reasonSummary(value);
        // No full response, headers, IDs or unlisted fields.
        return result;
    }
    function responseSummary(xhr) {
        try {
            var type = xhr.responseType;
            if (type === 'json') return xhr.response === null ? { json_state: 'json_null_or_invalid' } : businessSummary(xhr.response);
            if (type && type !== 'text') return { json_state: 'unsupported_response_type' };
            var text = xhr.responseText;
            if (!text) return { json_state: 'empty' };
            if (text.length > maxBody) return { json_state: 'size_limit' };
            try { return businessSummary(JSON.parse(text)); }
            catch (_) { return { json_state: 'invalid' }; }
        } catch (_) { return { json_state: 'unavailable' }; }
    }
    function observe(xhr, record) {
        var listeners = [];
        var timer;
        function cleanup() {
            try { clearTimeout(timer); } catch (_) {}
            listeners.forEach(function (pair) {
                try { removeEvent.call(xhr, pair[0], pair[1]); } catch (_) {}
            });
        }
        function finish(event) {
            try { finishSafely(event); } catch (_) {}
        }
        function finishSafely(event) {
            if (record.finished) return;
            record.finished = true;
            cleanup();
            if (records.get(xhr) !== record) return;
            var result = {
                event: event,
                request_id: record.id,
                elapsed_ms: Math.max(0, Math.round(performance.now() - record.started)),
                terminal_event: record.terminal || 'unknown'
            };
            Object.assign(result, record.parameters);
            if (event === 'request_complete') {
                try { result.http_status = xhr.status; } catch (_) {}
                try {
                    if (xhr.responseURL && !target(xhr.responseURL)) {
                        result.json_state = 'redirect_outside_scope';
                    } else Object.assign(result, responseSummary(xhr));
                } catch (_) { result.json_state = 'unavailable'; }
            }
            emit(result);
        }
        record.cleanup = cleanup;
        ['load', 'error', 'timeout', 'abort'].forEach(function (name) {
            var callback = function () { record.terminal = name; };
            addEvent.call(xhr, name, callback);
            listeners.push([name, callback]);
        });
        var end = function () { finish('request_complete'); };
        addEvent.call(xhr, 'loadend', end);
        listeners.push(['loadend', end]);
        timer = setTimeout(function () { finish('observation_window_elapsed'); }, 15000);
        record.sendThrew = function () { finish('send_threw'); };
    }
    function diagnosticOpen() {
        try {
            var old = records.get(this);
            if (old && old.cleanup) old.cleanup();
            records.delete(this);
        } catch (_) {}
        var value = originalOpen.apply(this, arguments);
        try {
            if (target(arguments[1]) && sequence < maxRequests)
                records.set(this, { id: ++sequence, parameters: parameterSummary(arguments[1]) });
        } catch (_) {}
        return value;
    }
    function diagnosticSend() {
        var record = records.get(this);
        if (record && record.started === undefined) {
            try {
                record.started = performance.now();
                observe(this, record);
                emit(Object.assign({ event: 'request_started', request_id: record.id }, record.parameters));
            } catch (_) { if (record.cleanup) record.cleanup(); }
        } else record = null;
        try { return originalSend.apply(this, arguments); }
        catch (error) {
            if (record && record.sendThrew) record.sendThrew();
            throw error;
        }
    }
    try {
        proto.open = diagnosticOpen;
        proto.send = diagnosticSend;
        if (proto.open !== diagnosticOpen || proto.send !== diagnosticSend) throw new Error('installation_failed');
        Object.defineProperty(window, marker, { value: true, configurable: true });
        emit({ event: 'observer_ready' });
    } catch (_) {
        try { if (proto.open === diagnosticOpen) proto.open = originalOpen; } catch (_) {}
        try { if (proto.send === diagnosticSend) proto.send = originalSend; } catch (_) {}
        emit({ event: 'observer_install_failed' });
    }
})();
