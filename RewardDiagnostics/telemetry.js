/* Passive, scoped evidence collection. Does not send or modify business requests. */
(function () {
    'use strict';
    var marker = '__bdsIncomeTelemetry040', handler = 'bds_reward_diag_040';
    if (window[marker] || !(location.hostname === 'baidu.com' || location.hostname.endsWith('.baidu.com'))) return;
    var sink = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers[handler];
    if (!sink || typeof sink.postMessage !== 'function') return;
    Object.defineProperty(window, marker, {value:true});
    var documentId = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 12);
    var sequence = 0, emitted = 0, maxRequests = 128;
    var images = new WeakMap(), nested = new WeakSet(), xhrs = new WeakMap(), urls = new Map();
    var add = window.EventTarget && EventTarget.prototype.addEventListener;
    var remove = window.EventTarget && EventTarget.prototype.removeEventListener;
    function emit(event, record, extra) {
        try {
            if (emitted++ >= 768) return;
            sink.postMessage(Object.assign({event:event, document_id:documentId,
                endpoint:'https://h2tcbox.baidu.com/ztbox'}, record ? record.safe : {}, extra || {}));
        } catch (_) {}
    }
    function scoped(value) {
        if (typeof value !== 'string' || value.length > 131072) return null;
        try {
            var u = new URL(value, location.href);
            return u.protocol === 'https:' && u.hostname === 'h2tcbox.baidu.com' && u.pathname === '/ztbox' ? u : null;
        } catch (_) { return null; }
    }
    function numeric(value) {
        return typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= 1e12 ||
            typeof value === 'string' && /^-?\d{1,12}(?:\.\d{1,6})?$/.test(value);
    }
    function payload(url, body) {
        var u = scoped(url);
        if (!u) return null;
        var data = u.searchParams.getAll('data');
        if (data.length === 0 && typeof body === 'string' && body.length <= 131072)
            data = new URLSearchParams(body).getAll('data');
        if (data.length !== 1) return null;
        try {
            var root = JSON.parse(data[0]), action = root && root.actiondata;
            if (!action || (action.id !== '10290' && action.id !== 10290)) return null;
            var content = action.content;
            if (!content || content.page !== 'y_mission_index') return null;
            var ext = content.ext, hasNum = !!ext && Object.prototype.hasOwnProperty.call(ext, 'num');
            var result = {event_id:10290, event_page:'y_mission_index', cash_num_present:hasNum};
            if (hasNum && numeric(ext.num)) result.cash_num = ext.num;
            result.cash_num_type = !hasNum ? 'absent' : ext.num === null ? 'null' : typeof ext.num;
            if (typeof content.type === 'string' && /^[A-Za-z0-9_]{1,48}$/.test(content.type)) result.event_type = content.type;
            if (typeof action.timestamp === 'number' && Number.isFinite(action.timestamp)) result.payload_timestamp_ms = action.timestamp;
            var command = u.searchParams.get('action');
            if (command === 'zpblog' || command === 'mpblog' || command === 'zubc') result.action = command;
            return {url:u.href, safe:result};
        } catch (_) { return null; }
    }
    function begin(value, body, transport) {
        if (sequence >= maxRequests) return null;
        var r = payload(value, body);
        if (!r) return null;
        r.safe.capture_id = ++sequence; r.safe.transport = transport;
        r.started = performance.now();
        // A resource entry has no request ID. Reused identical URLs cannot be
        // attributed to one of several API invocations with certainty.
        urls.set(r.url, urls.has(r.url) ? null : r);
        return r;
    }
    function watch(target, r, events) {
        var pairs = [], timer;
        function clean() {
            try { clearTimeout(timer); } catch (_) {}
            pairs.forEach(function (p) { try { remove.call(target, p[0], p[1]); } catch (_) {} });
        }
        r.finish = function (event, extra) {
            if (r.finished) return;
            r.finished = true; clean();
            emit(event, r, Object.assign({elapsed_ms:Math.max(0, Math.round(performance.now() - r.started))}, extra || {}));
        };
        try {
            events.forEach(function (name) {
                var callback = function () {
                    if (r.safe.transport === 'xhr') {
                        if (name !== 'loadend') { r.terminal = name; return; }
                        var extra = {terminal_event:r.terminal || 'unknown'};
                        try { extra.http_status = target.status; extra.final_endpoint_matches = !!scoped(target.responseURL); } catch (_) {}
                        r.finish('telemetry_xhr_complete', extra);
                    } else r.finish(name === 'load' ? 'telemetry_image_load' : 'telemetry_image_error');
                };
                add.call(target, name, callback); pairs.push([name, callback]);
            });
            timer = setTimeout(function () { r.finish('telemetry_observation_expired'); }, 20000);
        } catch (_) { clean(); emit('telemetry_listener_failed', r); }
    }
    function imageCall(img, value, originalCall, transport) {
        if (nested.has(img)) return originalCall();
        nested.add(img);
        var r;
        try {
            try {
                var previous = images.get(img);
                if (previous && previous.finish) previous.finish('telemetry_superseded');
                images.delete(img);
                r = begin(value, null, transport);
                if (r) { images.set(img, r); watch(img, r, ['load','error']); emit('telemetry_attempt', r); }
            } catch (_) {}
            var result;
            try { result = originalCall(); }
            catch (error) { if (r && r.finish) r.finish('telemetry_api_threw'); throw error; }
            if (r) emit('telemetry_handed_to_browser', r);
            return result;
        } finally { nested.delete(img); }
    }
    var installed = {image_property:false, image_attribute:false, xhr:false, beacon:false, resource_observer:false};
    try {
        var ip = HTMLImageElement.prototype, desc = Object.getOwnPropertyDescriptor(ip, 'src');
        if (desc && desc.set && desc.configurable) {
            Object.defineProperty(ip, 'src', Object.assign({}, desc, {set:function (value) {
                var self = this;
                return imageCall(self, value, function () { return desc.set.call(self, value); }, 'image_src');
            }})); installed.image_property = true;
        }
    } catch (_) {}
    try {
        var ep = Element.prototype, attribute = ep.setAttribute;
        function setAttribute(name, value) {
            var self = this, args = arguments;
            if (typeof name === 'string' && name.toLowerCase() === 'src' && self instanceof HTMLImageElement)
                return imageCall(self, value, function () { return attribute.apply(self, args); }, 'image_attribute');
            return attribute.apply(self, args);
        }
        ep.setAttribute = setAttribute;
        installed.image_attribute = ep.setAttribute === setAttribute;
    } catch (_) {}
    try {
        var xp = XMLHttpRequest.prototype, originalOpen = xp.open, originalSend = xp.send;
        function open() {
            var previous = xhrs.get(this);
            if (previous && previous.record && previous.record.finish) previous.record.finish('telemetry_superseded');
            xhrs.delete(this);
            var result = originalOpen.apply(this, arguments);
            try { if (scoped(arguments[1])) xhrs.set(this, {url:arguments[1], method:arguments[0]}); } catch (_) {}
            return result;
        }
        function send(body) {
            var info = xhrs.get(this), r;
            try {
                if (info && !info.sent) {
                    info.sent = true; r = begin(info.url, body, 'xhr'); info.record = r;
                    if (r) { watch(this, r, ['load','error','timeout','abort','loadend']); emit('telemetry_attempt', r); }
                }
            } catch (_) {}
            var result;
            try { result = originalSend.apply(this, arguments); }
            catch (error) { if (r && r.finish) r.finish('telemetry_api_threw'); throw error; }
            if (r) emit('telemetry_handed_to_browser', r);
            return result;
        }
        xp.open = open; xp.send = send;
        installed.xhr = xp.open === open && xp.send === send;
        if (!installed.xhr) { if (xp.open === open) xp.open = originalOpen; if (xp.send === send) xp.send = originalSend; }
    } catch (_) {
        try { if (xp && xp.open === open) xp.open = originalOpen; if (xp && xp.send === send) xp.send = originalSend; } catch (_) {}
    }
    try {
        var beacon = navigator.sendBeacon;
        if (typeof beacon === 'function') {
            function sendBeacon(url, body) {
                var r;
                try { r = begin(url, body, 'beacon'); if (r) emit('telemetry_attempt', r); } catch (_) {}
                var result;
                try { result = beacon.apply(this, arguments); }
                catch (error) { if (r) emit('telemetry_api_threw', r); throw error; }
                if (r) emit('telemetry_beacon_return', r, {queued:result === true});
                return result;
            }
            navigator.sendBeacon = sendBeacon;
            installed.beacon = navigator.sendBeacon === sendBeacon;
        }
    } catch (_) {}
    try {
        var resourceCount = 0;
        var observer = new PerformanceObserver(function (list) {
            try {
                list.getEntries().forEach(function (entry) {
                    if (resourceCount >= 128) return;
                    var p = payload(entry.name, null);
                    if (!p) return;
                    resourceCount++;
                    var r = urls.get(p.url), extra = {transport:'resource', capture_id:r ? r.safe.capture_id : 0,
                        correlation_ambiguous:urls.has(p.url) && !r};
                    ['startTime','duration','transferSize','encodedBodySize','decodedBodySize','responseStatus'].forEach(function (key) {
                        var v = entry[key]; if (typeof v === 'number' && Number.isFinite(v) && v >= 0) extra[key] = v;
                    });
                    if (typeof entry.initiatorType === 'string' && ['img','xmlhttprequest','beacon','fetch','other'].includes(entry.initiatorType)) extra.initiator = entry.initiatorType;
                    emit('telemetry_resource', p, extra);
                });
            } catch (_) {}
        });
        observer.observe({type:'resource', buffered:true}); installed.resource_observer = true;
    } catch (_) {}
    emit('telemetry_ready', null, installed);
})();
