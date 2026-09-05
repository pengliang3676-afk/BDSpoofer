'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/telemetry.js', 'utf8');

function url(options={}) {
    const data = {actiondata:{id:options.id ?? '10290',timestamp:1788618865000,
        content:{page:options.page ?? 'y_mission_index',type:'c_pv',ext:{num:options.num ?? '2.53',token:'PRIVATE_RESPONSE_TOKEN'}}},private:'PRIVATE_ACCOUNT'};
    if (options.noNum) delete data.actiondata.content.ext.num;
    return 'https://h2tcbox.baidu.com/ztbox?action=zpblog&uid=PRIVATE_UID&data=' + encodeURIComponent(JSON.stringify(data));
}
function fixture(options={}) {
    const messages=[], timers=new Map(), resources=[];
    let timerId=0, now=10;
    class Target {
        constructor() { this.listeners=new Map(); }
        addEventListener(name,cb) {
            if (options.failListener===name) throw new Error('listener unavailable');
            const list=this.listeners.get(name)||[];list.push(cb);this.listeners.set(name,list);
        }
        removeEventListener(name,cb) { this.listeners.set(name,(this.listeners.get(name)||[]).filter(f=>f!==cb)); }
        dispatch(name) {
            now+=2;
            if (typeof this['on'+name]==='function') this['on'+name]({type:name});
            for (const fn of [...(this.listeners.get(name)||[])]) fn({type:name});
        }
    }
    class Element extends Target {
        setAttribute(name,value) { this.attributeCalls=(this.attributeCalls||0)+1;this.attributeArgs=[name,value];if(typeof name==='string'&&name.toLowerCase()==='src'&&this instanceof Image) this.src=value;return 'attribute-result'; }
    }
    class Image extends Element {}
    Object.defineProperty(Image.prototype,'src',{configurable:!options.fixedImage,enumerable:true,
        get(){return this.source||'';},set(value){this.sourceCalls=(this.sourceCalls||0)+1;this.sourceArgument=value;if(this.setterError)throw this.setterError;this.source=new URL(String(value),'https://activity.baidu.com/').href;if(this.syncLoad)this.dispatch('load');return 'setter-result';}});
    class XHR extends Target {
        open(...args){this.openCalls=(this.openCalls||0)+1;this.openArgs=args;if(this.openError)throw this.openError;return 'open-result';}
        send(...args){this.sendCalls=(this.sendCalls||0)+1;this.sendArgs=args;if(this.sendError)throw this.sendError;if(this.syncLoad)this.complete();return 'send-result';}
        complete(type='load',status=200,final='https://h2tcbox.baidu.com/ztbox') {this.status=status;this.responseURL=final;this.dispatch(type);this.dispatch('loadend');}
        get responseText(){assert.fail('telemetry must not read unrelated response body');}
    }
    const navigator={sendBeacon(...args){this.beaconCalls=(this.beaconCalls||0)+1;this.beaconArgs=args;if(options.beaconError)throw options.beaconError;return options.beaconResult ?? true;}};
    class PO { constructor(cb){this.cb=cb;resources.push(this);} observe(config){this.config=config;if(options.noResource)throw new Error('not available');} }
    const ctx={URL,URLSearchParams,WeakMap,WeakSet,Map,EventTarget:Target,Element,HTMLImageElement:Image,XMLHttpRequest:XHR,navigator,
        location:{hostname:options.host||'activity.baidu.com',href:'https://activity.baidu.com/incentive/incentiveHome'},
        performance:{now:()=>now},PerformanceObserver:PO,
        setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);},
        webkit:{messageHandlers:{bds_reward_diag_040:{postMessage(v){if(options.sinkThrows)throw new Error('sink');messages.push(JSON.parse(JSON.stringify(v)));}}}}};
    ctx.window=ctx;vm.createContext(ctx);const install=()=>vm.runInContext(source,ctx);install();
    return {Image,Element,XHR,navigator,messages,ctx,timers,install,
        of:event=>messages.filter(x=>x.event===event),
        fireTimers(){for(const [id,fn] of [...timers]){timers.delete(id);fn();}},
        resource(entry){resources.at(-1).cb({getEntries:()=>[entry]});}};
}

test('image setter forwards unchanged URL once and preserves application load callback',()=>{
    const f=fixture(),img=new f.Image(),u=url();let called=0;img.onload=()=>called++;
    const setter=Object.getOwnPropertyDescriptor(f.Image.prototype,'src').set;
    assert.equal(setter.call(img,u),'setter-result');img.dispatch('load');
    assert.equal(img.sourceCalls,1);assert.equal(img.sourceArgument,u);assert.equal(img.src,u);assert.equal(called,1);
    assert.equal(f.of('telemetry_attempt')[0].cash_num,'2.53');
    assert.equal(f.of('telemetry_handed_to_browser').length,1);assert.equal(f.of('telemetry_image_load').length,1);
    assert.equal(f.timers.size,0);
    assert.equal(f.of('telemetry_image_load')[0].capture_id,f.of('telemetry_attempt')[0].capture_id);
});
test('local evidence strips URL query, tokens and all unlisted payload fields',()=>{
    const f=fixture(),img=new f.Image();img.src=url();img.dispatch('load');
    const text=JSON.stringify(f.messages);for(const secret of ['PRIVATE_UID','PRIVATE_ACCOUNT','PRIVATE_RESPONSE_TOKEN','actiondata','?action='])assert.ok(!text.includes(secret),secret);
    assert.equal(f.of('telemetry_attempt')[0].endpoint,'https://h2tcbox.baidu.com/ztbox');
});
test('only exact HTTPS host, path, event ID and page are observed',()=>{
    const f=fixture();for(const u of [url().replace('h2tcbox.baidu.com','evil.test'),url().replace('https:','http:'),url().replace('/ztbox?','/other?'),url({id:77}),url({page:'other'})]){
        const img=new f.Image();img.src=u;img.dispatch('load');assert.equal(img.sourceCalls,1);
    }
    assert.equal(f.messages.length,1);assert.equal(fixture({host:'evil.test'}).messages.length,0);
});
test('non-string URLs retain original conversion count and are not re-stringified for diagnostics',()=>{
    const f=fixture(),img=new f.Image();let conversions=0;const value={toString(){conversions++;return url();}};
    img.src=value;assert.equal(conversions,1);assert.equal(img.sourceArgument,value);assert.equal(f.messages.length,1);
});
test('setAttribute nesting does not double record or double invoke original setter',()=>{
    const f=fixture(),img=new f.Image(),u=url();
    assert.equal(img.setAttribute('SRC',u),'attribute-result');img.dispatch('load');
    assert.equal(img.attributeCalls,1);assert.equal(img.sourceCalls,1);assert.deepEqual(img.attributeArgs,['SRC',u]);
    assert.equal(f.of('telemetry_attempt').length,1);assert.equal(f.of('telemetry_attempt')[0].transport,'image_attribute');
    const div=new f.Element();div.setAttribute('src',u);assert.equal(f.of('telemetry_attempt').length,1);
});
test('retargeting image cleans old listeners and cannot attribute new load to old request',()=>{
    const f=fixture(),img=new f.Image();img.src=url();img.src='https://example.com/unrelated.png';img.dispatch('load');
    assert.equal(f.of('telemetry_superseded').length,1);assert.equal(f.of('telemetry_image_load').length,0);assert.equal(f.timers.size,0);
});
test('concurrent images have separate correlation IDs and callbacks',()=>{
    const f=fixture(),a=new f.Image(),b=new f.Image();a.src=url({num:'2.53'});b.src=url({num:'3.25'});b.dispatch('load');a.dispatch('error');
    assert.equal(f.of('telemetry_image_load')[0].cash_num,'3.25');assert.equal(f.of('telemetry_image_error')[0].cash_num,'2.53');
    assert.notEqual(f.of('telemetry_image_load')[0].capture_id,f.of('telemetry_image_error')[0].capture_id);
});
test('setter exception identity is preserved and no successful handoff is claimed',()=>{
    const f=fixture(),img=new f.Image(),error={};img.setterError=error;
    assert.throws(()=>{img.src=url();},e=>e===error);assert.equal(f.of('telemetry_api_threw').length,1);
    assert.equal(f.of('telemetry_handed_to_browser').length,0);assert.equal(f.timers.size,0);
});
test('observation expiry never cancels or retries the image request',()=>{
    const f=fixture(),img=new f.Image(),u=url();img.src=u;f.fireTimers();img.dispatch('load');
    assert.equal(img.src,u);assert.equal(img.sourceCalls,1);assert.equal(f.of('telemetry_observation_expired').length,1);assert.equal(f.of('telemetry_image_load').length,0);
});
test('malformed, ambiguous and oversized payloads do not interrupt original requests',()=>{
    const f=fixture();for(const u of [url()+'&data=%7B%7D','https://h2tcbox.baidu.com/ztbox?data=not-json',url()+'&x='+'x'.repeat(131072)]){
        const img=new f.Image();img.src=u;assert.equal(img.sourceArgument,u);assert.equal(img.sourceCalls,1);
    }assert.equal(f.messages.length,1);
});
test('missing and invalid cash values are distinguished and unsafe strings omitted',()=>{
    const f=fixture(),a=new f.Image(),b=new f.Image(),c=new f.Image();a.src=url({noNum:true});b.src=url({num:'PRIVATE_CASH'});c.src=url({num:2.53});
    const [r,s,t]=f.of('telemetry_attempt');assert.equal(r.cash_num_present,false);assert.equal(r.cash_num_type,'absent');
    assert.equal(s.cash_num_present,true);assert.equal(s.cash_num,undefined);assert.equal(t.cash_num,2.53);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CASH'));
});
test('XHR GET/POST preserve method arguments, body, return values and response',()=>{
    for(const post of [false,true]){
        const f=fixture(),x=new f.XHR(),u=url(),body='data='+new URL(u).searchParams.get('data');
        const encoded='data='+encodeURIComponent(new URL(u).searchParams.get('data'));
        assert.equal(x.open(post?'POST':'GET',post?'https://h2tcbox.baidu.com/ztbox?action=zpblog':u,true),'open-result');
        const sent=post?encoded:undefined;assert.equal(x.send(sent),'send-result');x.complete();
        assert.equal(x.openCalls,1);assert.equal(x.sendCalls,1);assert.equal(x.sendArgs[0],sent);
        assert.equal(f.of('telemetry_xhr_complete')[0].http_status,200);assert.equal(f.of('telemetry_xhr_complete')[0].final_endpoint_matches,true);
        assert.equal(f.of('telemetry_attempt')[0].cash_num,'2.53');
    }
});
test('XHR exceptions, redirects, abort and reopen remain distinguishable',()=>{
    const f=fixture(),x=new f.XHR(),error={};x.open('GET',url());x.sendError=error;assert.throws(()=>x.send(),e=>e===error);assert.equal(f.of('telemetry_api_threw').length,1);
    const y=new f.XHR();y.open('GET',url());y.send();y.complete('load',200,'https://example.com/');assert.equal(f.of('telemetry_xhr_complete')[0].final_endpoint_matches,false);
    const z=new f.XHR();z.open('GET',url());z.send();z.open('GET','https://example.com/');z.send();z.complete();assert.equal(f.of('telemetry_superseded').length,1);
    const v=new f.XHR();v.open('GET',url());v.send();v.complete('abort',0);assert.equal(f.of('telemetry_xhr_complete').at(-1).terminal_event,'abort');
});
test('Beacon acceptance remains queue status and preserves exact body and return value',()=>{
    for(const result of [true,false]){
        const f=fixture({beaconResult:result});const body='data='+encodeURIComponent(new URL(url()).searchParams.get('data'));
        assert.equal(f.navigator.sendBeacon('https://h2tcbox.baidu.com/ztbox?action=zpblog',body),result);
        assert.equal(f.navigator.beaconCalls,1);assert.equal(f.navigator.beaconArgs[1],body);
        assert.equal(f.of('telemetry_beacon_return')[0].queued,result);assert.equal(f.of('telemetry_image_load').length,0);
    }
    const error={},g=fixture({beaconError:error});assert.throws(()=>g.navigator.sendBeacon(url()),e=>e===error);
});
test('binary/opaque Beacon body is not consumed or replaced',()=>{
    const f=fixture(),body={toString(){assert.fail('must not coerce body');}};
    assert.equal(f.navigator.sendBeacon('https://h2tcbox.baidu.com/ztbox',body),true);assert.equal(f.navigator.beaconArgs[1],body);assert.equal(f.of('telemetry_attempt').length,0);
});
test('resource observations carry payload evidence with independent status, not synthetic send proof',()=>{
    const f=fixture(),u=url();f.resource({name:u,initiatorType:'img',startTime:15,duration:30,transferSize:0,responseStatus:0});
    const r=f.of('telemetry_resource')[0];assert.equal(r.capture_id,0);assert.equal(r.cash_num,'2.53');assert.equal(r.responseStatus,0);assert.equal(f.of('telemetry_handed_to_browser').length,0);
    const img=new f.Image();img.src=u;f.resource({name:u,initiatorType:'img',responseStatus:200});assert.equal(f.of('telemetry_resource').at(-1).capture_id,f.of('telemetry_attempt')[0].capture_id);
});
test('installation is idempotent and reports missing support without changing app success',()=>{
    const f=fixture();const setter=Object.getOwnPropertyDescriptor(f.Image.prototype,'src').set;f.install();assert.equal(Object.getOwnPropertyDescriptor(f.Image.prototype,'src').set,setter);assert.equal(f.of('telemetry_ready').length,1);
    const g=fixture({fixedImage:true,noResource:true});assert.equal(g.of('telemetry_ready')[0].image_property,false);assert.equal(g.of('telemetry_ready')[0].resource_observer,false);
    const img=new g.Image();img.setAttribute('src',url());img.dispatch('load');assert.equal(g.of('telemetry_image_load').length,1);
});
test('identical request URLs do not produce a falsely unique resource correlation',()=>{
    const f=fixture(),u=url(),a=new f.Image(),b=new f.Image();a.src=u;b.src=u;
    f.resource({name:u,initiatorType:'img',responseStatus:200});
    assert.equal(f.of('telemetry_resource')[0].capture_id,0);assert.equal(f.of('telemetry_resource')[0].correlation_ambiguous,true);
    a.dispatch('load');b.dispatch('load');assert.equal(f.of('telemetry_image_load').length,2);
});
test('listener and sink failures cannot stop app setters, sends, or callbacks',()=>{
    const f=fixture({failListener:'error'}),img=new f.Image();img.src=url();assert.equal(img.sourceCalls,1);assert.equal(f.of('telemetry_listener_failed').length,1);
    assert.ok([...img.listeners.values()].every(a=>a.length===0));
    const g=fixture({sinkThrows:true}),other=new g.Image();other.src=url();other.dispatch('load');assert.equal(other.sourceCalls,1);
});
test('request count is bounded and synchronous image completion remains observable',()=>{
    const f=fixture(),img=new f.Image();img.syncLoad=true;img.src=url();assert.equal(f.of('telemetry_image_load').length,1);
    for(let i=0;i<130;i++){const x=new f.Image();x.src=url();x.dispatch('load');}
    assert.equal(f.of('telemetry_attempt').length,128);assert.equal(f.of('telemetry_handed_to_browser').length,128);
});
