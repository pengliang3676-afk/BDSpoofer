'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/observer.js', 'utf8');

function fixture(options = {}) {
    const messages = [], timers = new Map();
    let nextTimer = 0, now = 10;
    class XHR {
        constructor() {
            this.listeners = new Map();
            this.responseType = '';
            this.responseURL = '';
            this.status = 0;
            this.reads = 0;
            this.openCalls = this.sendCalls = 0;
        }
        open(...args) {
            this.openCalls++;
            this.openArgs = args;
            if (this.openError) throw this.openError;
            return 'original-open-result';
        }
        send(...args) {
            this.sendCalls++;
            this.sendArgs = args;
            if (this.sendError) throw this.sendError;
            if (this.syncReply) this.complete(this.syncReply);
            return 'original-send-result';
        }
        addEventListener(name, cb) {
            if (options.failListener === name) throw new Error('listener installation');
            const list = this.listeners.get(name) || [];
            list.push(cb);
            this.listeners.set(name, list);
        }
        removeEventListener(name, cb) {
            this.listeners.set(name, (this.listeners.get(name) || []).filter(x => x !== cb));
        }
        dispatch(name) {
            if (typeof this['on' + name] === 'function') this['on' + name]({type:name});
            for (const cb of [...(this.listeners.get(name) || [])]) cb({type:name});
        }
        get responseText() {
            this.reads++;
            if (this.readError) throw this.readError;
            return this.text;
        }
        complete(text, terminal = 'load', status = 200) {
            this.text = text;
            this.status = status;
            now += 25;
            this.dispatch(terminal);
            this.dispatch('loadend');
        }
    }
    const context = {
        XMLHttpRequest: XHR, URL,
        location: {hostname:options.host || 'mbd.baidu.com', href:'https://mbd.baidu.com/newspage/activity'},
        webkit:{messageHandlers:{bds_reward_diag_020:{postMessage(value) {
            if (options.sinkThrows) throw new Error('sink unavailable');
            messages.push(JSON.parse(JSON.stringify(value)));
        }}}},
        performance:{now:() => now},
        setTimeout(fn) { timers.set(++nextTimer, fn); return nextTimer; },
        clearTimeout(id) { timers.delete(id); }
    };
    context.window = context;
    vm.createContext(context);
    const savedConstructor = XHR;
    function install() { vm.runInContext(source, context); }
    install();
    function start(url = '/incentive/uanti?token=REQUEST_SECRET') {
        const xhr = new savedConstructor();
        xhr.open('GET', url, true);
        xhr.send(null);
        return xhr;
    }
    return {XHR, messages, context, timers, install, start,
        fireTimers() { for (const [id, fn] of [...timers]) { timers.delete(id); fn(); } },
        completeRecord() { return messages.findLast(m => m.event === 'request_complete'); }};
}

test('preserves call arguments, return values, response and application callbacks', () => {
    const f = fixture(), xhr = new f.XHR(), body = {opaque:'BODY_SECRET'};
    let callbackText, callbackCount = 0;
    xhr.onload = () => { callbackCount++; callbackText = xhr.responseText; };
    assert.equal(xhr.open('POST', '/incentive/uanti', true, 'name', 'password'), 'original-open-result');
    assert.deepEqual(xhr.openArgs, ['POST','/incentive/uanti',true,'name','password']);
    assert.equal(xhr.send(body), 'original-send-result');
    assert.equal(xhr.sendArgs[0], body);
    const response = '{"errno":0,"data":{"isSafe":false},"token":"RESPONSE_SECRET","errmsg":"request failed"}';
    xhr.complete(response);
    assert.equal(callbackCount, 1);
    assert.equal(callbackText, response);
    assert.equal(xhr.openCalls, 1);
    assert.equal(xhr.sendCalls, 1);
    assert.equal(f.completeRecord().is_safe_value, false);
    assert.equal(f.completeRecord().business_code_is_number_zero, true);
    assert.equal(f.completeRecord().elapsed_ms, 25);
    assert.equal(f.timers.size, 0);
    const serialized = JSON.stringify(f.messages);
    for (const secret of ['BODY_SECRET','RESPONSE_SECRET','PRIVATE','password','name','token']) {
        assert.ok(!serialized.includes(secret), secret);
    }
});
test('exact endpoint and HTTPS Baidu host only; unrelated responses are not read', () => {
    const f = fixture();
    for (const url of ['/other','/incentive/uanti/','https://baidu.com.evil.test/incentive/uanti',
        'https://evilbaidu.com/incentive/uanti','http://mbd.baidu.com/incentive/uanti']) {
        const xhr = f.start(url);
        xhr.complete('PRIVATE');
        assert.equal(xhr.reads, 0);
    }
    assert.equal(f.messages.length, 1);
    f.start('https://www.baidu.com/incentive/uanti?x=PRIVATE').complete('{"errno":0,"data":{"isSafe":true}}');
    assert.equal(f.completeRecord().is_safe_truthy, true);
    assert.ok(!JSON.stringify(f.messages).includes('PRIVATE'));
    assert.equal(fixture({host:'evil.test'}).messages.length, 0);
});
test('preserves exact open/send exceptions and diagnostic failures do not break send', () => {
    const f = fixture(), x = new f.XHR(), openError = {}, sendError = {};
    x.openError = openError;
    assert.throws(() => x.open('GET','/incentive/uanti'), e => e === openError);
    delete x.openError;
    x.open('GET','/incentive/uanti');
    x.sendError = sendError;
    assert.throws(() => x.send('BODY'), e => e === sendError);
    assert.equal(f.messages.at(-1).event, 'send_threw');
    assert.equal(f.timers.size, 0);
    const failed = fixture({failListener:'loadend'}), y = failed.start();
    y.complete('{}');
    assert.equal(y.sendCalls, 1);
    assert.ok([...y.listeners.values()].every(list => list.length === 0));
    const brokenSink = fixture({sinkThrows:true}), z = brokenSink.start();
    z.complete('{}');
    assert.equal(z.sendCalls, 1);
});
test('JSON and strict errno types distinguish rejected and accepted eligibility', () => {
    const cases = [
        ['{"errno":0,"data":{"isSafe":true}}', true, true, 'boolean'],
        ['{"errno":0,"data":{"isSafe":false}}', true, false, 'boolean'],
        ['{"errno":"0","data":{"isSafe":1}}', false, true, 'number'],
        ['{"errno":7,"data":{"isSafe":true}}', false, true, 'boolean'],
        ['{"errno":0,"data":{"isSafe":"0"}}', true, true, 'string'],
        ['{"errno":0,"data":{"isSafe":null}}', true, false, 'null']
    ];
    for (const [body, zero, truthy, type] of cases) {
        const f = fixture(); f.start().complete(body); const r = f.completeRecord();
        assert.equal(r.business_code_is_number_zero, zero);
        assert.equal(r.is_safe_truthy, truthy);
        assert.equal(r.is_safe_type, type);
    }
});
test('records absent fields, malformed, oversized, empty and inaccessible responses', () => {
    for (const [body, state] of [['not-json','invalid'],['','empty'],['x'.repeat(65537),'size_limit'],['null','valid']]) {
        const f = fixture(); f.start().complete(body);
        assert.equal(f.completeRecord().json_state, state);
    }
    const f = fixture(); f.start().complete('{"errno":0,"data":{}}');
    assert.equal(f.completeRecord().is_safe_present, false);
    const g = fixture(), x = g.start(); x.readError = new Error(); x.complete('{}');
    assert.equal(g.completeRecord().json_state, 'unavailable');
});
test('handles JSON response type without coercing types and refuses binary data', () => {
    const f = fixture(), x = f.start();
    x.responseType = 'json'; x.response = {errno:0,data:{isSafe:0}};
    x.complete('PRIVATE');
    assert.equal(x.reads, 0);
    assert.equal(f.completeRecord().is_safe_truthy, false);
    const g = fixture(), y = g.start(); y.responseType = 'json'; y.response = null; y.complete('');
    assert.equal(g.completeRecord().json_state, 'json_null_or_invalid');
    const h = fixture(), z = h.start(); z.responseType = 'arraybuffer'; z.complete('PRIVATE');
    assert.equal(z.reads, 0);
    assert.equal(h.completeRecord().json_state, 'unsupported_response_type');
});
test('does not read redirected response outside allowed endpoint', () => {
    const f = fixture(), x = f.start();
    x.responseURL = 'https://passport.baidu.com/login';
    x.complete('PRIVATE');
    assert.equal(x.reads, 0);
    assert.equal(f.completeRecord().json_state, 'redirect_outside_scope');
});
test('transport events remain distinct; observation watchdog never aborts request', () => {
    for (const terminal of ['error','timeout','abort']) {
        const f = fixture(); f.start().complete('', terminal, 0);
        assert.equal(f.completeRecord().terminal_event, terminal);
        assert.equal(f.completeRecord().http_status, 0);
    }
    const f = fixture(), x = f.start();
    x.abort = () => assert.fail('observer must not abort');
    f.fireTimers();
    assert.equal(f.messages.at(-1).event, 'observation_window_elapsed');
    assert.equal(f.messages.at(-1).terminal_event, 'unknown');
    x.complete('{"errno":0}');
    assert.equal(f.completeRecord(), undefined);
});
test('works for captured constructor and synchronous completion; duplicate installation is inert', () => {
    const f = fixture();
    const open = f.XHR.prototype.open;
    f.install();
    assert.equal(f.XHR.prototype.open, open);
    const x = new f.XHR();
    x.syncReply = '{"errno":0,"data":{"isSafe":true}}';
    x.open('GET','/incentive/uanti'); x.send();
    assert.equal(f.messages.filter(m => m.event === 'observer_ready').length, 1);
    assert.equal(f.messages.filter(m => m.event === 'request_complete').length, 1);
});
test('reopening XHR cleans listeners; request cap bounds observation', () => {
    const f = fixture(), x = f.start();
    x.open('GET','/other'); x.send(); x.complete('PRIVATE');
    assert.equal(x.reads, 0);
    assert.equal(f.timers.size, 0);
    for (let i=0;i<130;i++) f.start().complete('{"errno":0}');
    assert.equal(f.messages.filter(m => m.event === 'request_complete').length, 127);
});
test('object URLs never trigger a second custom string conversion', () => {
    const f = fixture(), url = {toString(){ assert.fail('observer must not stringify'); }};
    const x = f.start(url); x.complete('PRIVATE');
    assert.equal(x.reads, 0);
    assert.equal(x.openArgs[1], url);
});
test('unsafe business field contents are omitted rather than copied', () => {
    const f = fixture();
    f.start().complete(JSON.stringify({errno:'PRIVATE_TOKEN',data:{isSafe:'PRIVATE_ACCOUNT'},BDUSS:'PRIVATE_COOKIE'}));
    const r = f.completeRecord();
    assert.equal(r.business_code_present, true);
    assert.equal(r.business_code, undefined);
    assert.equal(r.is_safe_value, undefined);
    assert.equal(r.is_safe_truthy, true);
    assert.ok(!JSON.stringify(f.messages).includes('PRIVATE'));
});

test('records only security parameter presence and emptiness, never its value', () => {
    for (const [query, present, nonempty, placeholder, count] of [
        ['',false,false,false,0],
        ['?zid=',true,false,false,1],
        ['?zid=%20',true,false,false,1],
        ['?zid=null',true,true,true,1],
        ['?zid=undefined',true,true,true,1],
        ['?zid=ZID_SECRET_VALUE',true,true,false,1],
        ['?zid=&zid=ZID_SECRET_VALUE',true,true,false,2]
    ]) {
        const f=fixture(); f.start('/incentive/uanti'+query).complete('{"errno":0,"data":{"isSafe":false}}');
        for (const r of f.messages.filter(x=>x.event.startsWith('request_'))) {
            assert.equal(r.security_param_present,present);
            assert.equal(r.security_param_nonempty,nonempty);
            assert.equal(r.security_param_placeholder,placeholder);
            assert.equal(r.security_param_count,count);
        }
        assert.ok(!JSON.stringify(f.messages).includes('ZID_SECRET_VALUE'));
    }
});
test('retains bounded reason fields with credentials and identifiers redacted', () => {
    const f=fixture();
    const reason='token=PRIVATE_SECRET contact abc@example.com 13812345678 https://example.com/private ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    f.start().complete(JSON.stringify({errno:0,errmsg:'ok',data:{isSafe:false,reasonCode:123,reason,
        account:{name:'PRIVATE_NAME'},unknown:'PRIVATE_OTHER'}}));
    const r=f.completeRecord();
    assert.equal(r.reason_fields['data.reasonCode'],123);
    assert.equal(r.reason_fields['root.errmsg'],'ok');
    assert.ok(r.reason_fields['data.reason'].includes('[redacted]'));
    for (const v of ['PRIVATE_SECRET','abc@example.com','13812345678','example.com/private','ABCDEFGHIJKLMNOPQRSTUVWXYZ','PRIVATE_NAME','PRIVATE_OTHER'])
        assert.ok(!JSON.stringify(r).includes(v),v);
});
test('limits reason text size and leaves the original response intact', () => {
    const f=fixture(), x=f.start();
    const body=JSON.stringify({errno:0,errmsg:'x'.repeat(5000),
        data:{isSafe:false,reason:'说明'.repeat(500),message:'更多说明'.repeat(500),reason_code:7}});
    x.complete(body);
    const reasons=f.completeRecord().reason_fields;
    assert.ok(Object.keys(reasons).length<=8);
    assert.ok(Object.values(reasons).filter(v=>typeof v==='string').reduce((n,v)=>n+v.length,0)<=256);
    assert.equal(x.responseText,body);
});
