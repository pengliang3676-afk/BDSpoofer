from pathlib import Path
import plistlib,re,subprocess
root=Path(__file__).resolve().parents[1]
plugin=(root/'BDSpoofer.m').read_text(encoding='utf-8')
manager=(root/'CraneManager/BDSCraneManager.m').read_text(encoding='utf-8')
policy=(root/'Shared/BDSConfigPolicy.h').read_text(encoding='utf-8')
blocker=(root/'Shared/BDSCashTelemetryBlocker.h').read_text(encoding='utf-8')
release=(root/'RELEASE_UI1.md').read_text(encoding='utf-8')
build=(root/'scripts/build_release_xcode.sh').read_text(encoding='utf-8')
config=plistlib.loads((root/'bdspoofer_config.plist').read_bytes())
items=re.findall(r'@\{@"key":@"([^"]+)",@"name":@"[^"]+"(,@"off":@YES)?\}',policy)
assert len(items)==26
regular=[key for key,off in items if not off];risk=[key for key,off in items if off]
assert len(regular)==20 and len(risk)==6
assert all(config[k] is True for k in regular)
assert all(config[k] is False for k in risk)
assert config['bypassJailbreakDetect'] is False  # 9.30-10 起默认关闭
assert config['spoofScreen'] is False and config['configVersion']==188
assert config['blockStatCashTelemetry'] is False
assert 'blockStatCashTelemetry' in policy and 'blockStatCashTelemetry' in plugin
assert '收益额上报：%@' in plugin and '? @"已开启" : @"已关闭"' in plugin
assert all(config['spoofBaiduTargeted'+x] is False for x in ['', 'System','Model','Screen','UA','Push'])
for text in ['一键随机整套基础参数','一键随机整套高级参数','一键随机定向指纹参数','反关联项','诊断自检','恢复安全']:assert text in plugin,text
for text in ['一键随机基础整套设置','一键随机高级整套设置','一键随机定向指纹设置','反关联项','恢复安全']:assert text in manager,text
for text in ['基础功能：当前功能状态  %@','高级功能：%@','定向指纹：%@','反关联增强：%@','尚未执行一键随机']:
    assert text in plugin,text
assert '百度身份参数 · 系统硬件参数 · 防越狱检测' not in plugin
assert '已开启（%lu 项）' not in plugin
assert 'cfgStr(@"deviceProfileName", cfgStr(@"hwMachine", @"未设置"))' in plugin
assert 'cfgStr(@"targetedDeviceProfileName", cfgStr(@"targetedHwMachine", @"未设置"))' in plugin
settings_ui=(root/'Shared/BDSSettingsUI.h').read_text(encoding='utf-8')
assert 'usesCompactActionRow' in settings_ui and 'UIStackViewDistributionFillEqually' in settings_ui
assert 'i==5 ? UIColor.systemRedColor' not in settings_ui
assert 'CGRectMake(0,0,width,8)' in manager and 'CGRectMake(0,0,width,100)' not in manager
assert 'CGRectMake(0,0,width,232)' in manager and 'layoutFooterButtons' in manager
assert 'viewWithTag:1003' in manager and 'viewWithTag:1004' in manager and 'viewWithTag:1005' not in manager
assert 'closeApp' not in manager and 'NSSelectorFromString(@"suspend")' not in manager
assert 'config[@"deviceProfileName"] ?: config[@"hwMachine"]' in manager
assert 'config[@"targetedDeviceProfileName"] ?: config[@"targetedHwMachine"]' in manager
assert 'NSString *currentSuffix = @"（当前）"' in manager and 'UIColor.systemRedColor' in manager
assert 'page.title=@"卐解 1.8.1 UI1.3 9.30-10"' in plugin
assert 'didRandomize%@%@' in policy
for text in ['BDSMarkRandomModeRun','BDSRandomModeWasRun','BDSConfigForPersistentStorage']:
    assert text in plugin+manager+policy,text
assert 'BDSCleanContainerDisplayName' in manager and '（默认）' in manager
assert 'numberOfLines = 3' in manager and 'sideInset=18.0' in manager
targeted_values=['targetedDeviceProfileName','targetedSystemVersion','targetedSystemBuild','targetedHwMachine','targetedHwModel','targetedScreenHwMachine','targetedScreenWidth','targetedScreenHeight','targetedScreenScale','targetedNativeScreenWidth','targetedNativeScreenHeight','targetedUASystemVersion','targetedUASystemBuild','targetedPushDeviceProfileName','targetedPushHwMachine','targetedPushHwModel','targetedGeneratedAt']
sparse=dict(config)
for key in targeted_values:sparse.pop(key,None)
sparse.pop('managerResolvedPath',None)
sparse.update(managerContainerIdentifier='12345678-1234-1234-1234-123456789012',managerGeneratedAt=1.0,managerProfileVersion=103,managerRandomMode='basic',didRandomizeBasic=True)
assert len(plistlib.dumps(sparse,fmt=plistlib.FMT_XML,sort_keys=False))<4096
assert 'g_rewardProbe' not in plugin
assert 'BDSInstallCashSpoofing' not in plugin and 'arc4random_uniform(101)' not in plugin
assert 'dataTaskWithRequest' not in blocker and 'willPerformHTTPRedirection' not in blocker
for text in ['h2tcbox.baidu.com','/ztbox','zpblog','10290','y_mission_index','c_pv','ext[@"num"]']:
    assert text in blocker,text
assert 'BDSInstallCashTelemetryBlocking();' in plugin
assert plugin.count('loadConfig();') >= 3
assert '0.50' not in release and '触发风控' not in release
assert 'BDSpoofer_1.8.1_UI1.3_9.30-10.dylib' in build and 'UI1.1.dylib' not in build
assert 'BDSpooferCraneManager_1.0.2-ui1_9.30-10_RootHide.deb' in build
assert 'BDSLoginDeviceDict' in plugin and 'ssologin' in plugin
assert 'BDSPassEncryptedDi' in plugin and 'deviceInfoForLogin' in plugin
assert 'BDSPassEnsureDVIF' in plugin and 'bds_my_uname' in plugin and '{"uname"' in plugin
assert 'self.title = @"卍解 1.0.2 9.30-10"' in manager
assert '[verified isEqualToDictionary:config]' in manager
assert 'targetedScreenHwMachine' in plugin and 'targetedScreenHwMachine' in manager
def function(text,name):
    # 支持 static C 函数与 Objective-C 实例/类方法两种形态。
    # 方法名在 @interface 里也有声明（以 ';' 结尾、没有函数体），必须跳过声明行，
    # 否则会从声明处一路括号配对吃到下一个函数。
    def pick(pattern):
        for m in re.finditer(pattern,text,re.M):
            brace=text.find('{',m.start())
            if brace<0: continue
            if ';' in text[m.end():brace]: continue
            return m,brace
        return None,None
    match,pos=pick(r'^static [^\n]*\b'+name+r'\(')
    if not match: match,pos=pick(r'^[-+]\s*\([^)\n]*\)\s*'+name+r'\b')
    assert match,name
    stripped=re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m[0]),text)
    depth=0
    for i in range(pos,len(text)):
        depth+=(stripped[i]=='{')-(stripped[i]=='}')
        if depth==0:return text[match.start():i+1]
    raise AssertionError(name)
def plugin_devices(text):
    body=function(text,'BDSDeviceProfiles')
    blocks=re.findall(r'@\{@"name":\s*@"[^"]+".*?@"disks":\s*@\[(.*?)\]\}',body,re.S)
    records={}
    for block in re.finditer(r'@\{@"name":\s*@"[^"]+".*?@"disks":\s*@\[(.*?)\]\}',body,re.S):
        item=block.group(0)
        string=lambda key: re.search(r'@"'+key+r'":\s*@"([^"]+)"',item).group(1)
        number=lambda key: int(re.search(r'@"'+key+r'":\s*@(\d+)',item).group(1))
        disks=tuple(map(int,re.findall(r'@(\d+)',block.group(1))))
        machine=string('machine')
        records[machine]=(string('name'),string('model'),number('width'),number('height'),
            number('nativeWidth'),number('nativeHeight'),number('scale'),number('memory'),disks)
    return records
def manager_devices(text):
    body=function(text,'BDSDeviceProfiles')
    pattern=(r'BDSDevice\(@"([^"]+)",\s*@"([^"]+)",\s*@"([^"]+)",\s*'
             r'(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*'
             r'@\[(.*?)\],\s*@"[^"]+",\s*\d+\)')
    records={}
    for values in re.findall(pattern,body,re.S):
        name,machine,model,*rest=values
        numbers=tuple(map(int,rest[:6]))
        disks=tuple(map(int,re.findall(r'@(\d+)',rest[6])))
        records[machine]=(name,model,*numbers,disks)
    return records
plugin_pool=plugin_devices(plugin);manager_pool=manager_devices(manager)
assert len(plugin_pool)==37 and plugin_pool==manager_pool
plugin_systems=re.findall(r'BDSSystem\(@"([^"]+)",\s*@"([^"]+)"\)',function(plugin,'BDSSystemProfiles'))
manager_systems=re.findall(r'BDSSystem\(@"([^"]+)",\s*@"([^"]+)"\)',function(manager,'BDSSystemProfiles'))
assert plugin_systems==manager_systems and len(plugin_systems)>50
base=subprocess.check_output(['git','show','b65d42ab33948455ef84e57d109d0dbede2a1b72:BDSpoofer.m'],cwd=root).decode('utf-8')
# 9.30-10 起这些是“故意改动”的函数，因此不再做整函数基线比对：
#   bds_is_suspicious_dlopen_path（分量边界匹配 + /private/var/jb）
#   bds_my_dlopen / bds_my_dlopen_preflight（去掉固定哨兵路径、orig 判空）
#   bds_perform_rebinding_with_section（页对齐、orig 只捕获一次、symtab 边界）
#   bds_my_stat/lstat/access/fopen/opendir（新增 orig 判空，属于纯增量加固）
# bds_c_is_jailbreak_path 必须与基线逐字节一致；上面那五个 C 包装函数要求
# “去掉新增判空行之后”仍与基线一致，即改动只能是加判空，语义不许动。
assert function(plugin,'bds_c_is_jailbreak_path')==function(base,'bds_c_is_jailbreak_path')
def strip_guards(text, name):
    body=function(text,name)
    return '\n'.join(l.strip() for l in body.splitlines() if 'if (!orig_' not in l)
for name in ['bds_my_stat','bds_my_lstat','bds_my_access','bds_my_fopen','bds_my_opendir']:
    assert strip_guards(plugin,name)==strip_guards(base,name),name
for path in ['bdspoofer_config.plist','CraneManager/Info.plist','CraneManager/BDSCraneManager.entitlements','CraneManager/BDSCraneManager.libSandy.plist']:plistlib.loads((root/path).read_bytes())
manager_info=plistlib.loads((root/'CraneManager/Info.plist').read_bytes())
assert manager_info['CFBundleVersion']=='9.30.10' and manager_info['CFBundleShortVersionString']=='1.0.2-9.30.10'
assert 'CPU iPhone OS ' in plugin and 'setCustomUserAgent:' in plugin
assert 'if (hw.length && f.count > 3) f[3] = hw;' in plugin
assert 'if (sv.length && f.count > 4) f[4] = sv;' in plugin
assert 'if (f.count > 27)' in plugin and 'cfgStr(@"deviceModel", @"iPhone")' in plugin
assert 'f[3].length' not in plugin and 'f[4].length' not in plugin
assert 'UIApplicationExitsOnSuspend' not in manager_info
# ---- 9.30-10：开关生效、X/M 语义一致、随机池、健壮性 ----
# 金额阻断必须每次请求都读开关，否则“关掉开关仍在拦”。
assert 'static BOOL (*BDSCashTelemetrySwitchProvider)(void)' in blocker
assert 'if (!BDSCashTelemetrySwitchIsOn()) return NO;' in blocker
assert 'static BOOL BDSCashTelemetrySwitchEnabled(void)' in plugin
assert 'BDSCashTelemetrySwitchProvider = BDSCashTelemetrySwitchEnabled;' in plugin
# 金额拦截只在开关打开时安装（9.30-10 起如此，与 9.28-03 一致）；
# 但判定入口必须每次请求读开关，否则“关掉开关仍在拦”。
assert 'if (!BDSCashTelemetrySwitchIsOn()) return NO;' in blocker
assert 'BDSCashTelemetrySwitchProvider = BDSCashTelemetrySwitchEnabled;' in plugin
assert 'dispatch_once(&onceToken' in blocker and 'registerClass:BDSCashTelemetryBlockProtocol.class' in blocker
assert 'arrayByAddingObject:BDSCashTelemetryBlockProtocol.class' in blocker
for text2 in ["typeof window.__bdsBlockStatCashTelemetry==='boolean'","navigator.sendBeacon","window.fetch","XMLHttpRequest.prototype.open"]:
    assert text2 in blocker,text2
assert 'NSLog' not in blocker
advanced=function(plugin,'randomizeAdvancedProfile')
assert 'BDSRandomIdentityValues()' in advanced
assert 'spoofBaiduSDK"] = @YES' not in advanced and 'spoofAdvertisingIdentifiers"] = @YES' not in advanced
assert 'static NSArray<NSDictionary *> *BDSRandomEligibleProfiles(void)' in plugin
assert '[device[@"machine"] isEqualToString:@"iPhone12,8"]' in plugin
assert '[device[@"machine"] isEqualToString:@"iPhone12,8"]' in manager
assert 'BDSRandomEligibleProfiles() mutableCopy' in plugin and 'BDSRandomEligibleProfiles();' in plugin
dlopen_match=function(plugin,'bds_is_suspicious_dlopen_path')
assert 'int atComponentStart' in dlopen_match and 'hit[-1]' in dlopen_match
assert '"/private/var/jb"' in dlopen_match
assert 'strstr(path, badPaths[i])' not in dlopen_match
assert 'stat/access/fopen \u5df2\u62e6\u622a' not in plugin
assert 'C\u51fd\u6570\u68c0\u6d4b\uff1a\u5df2\u62e6\u622a %llu \u6b21 / \u547d\u4e2d %llu \u6b21' in plugin
assert 'static vm_address_t bds_page_mask(void)' in plugin
assert 'page_mask' in function(plugin,'bds_perform_rebinding_with_section')
rebind=function(plugin,'bds_perform_rebinding_with_section')
assert '*(cur->rebindings[j].replaced) == NULL' in rebind
# 关键回归：原函数捕获不能挑节类型，否则惰性槽位记不到原函数，
# orig_* 恒为 NULL，替换函数一律返回失败，App 一启动就闪退。
assert 'S_NON_LAZY_SYMBOL_POINTERS' not in rebind
assert 'if (!orig_stat) { errno = ENOENT; return -1; }' in plugin
assert 'if (!orig_opendir) { errno = ENOENT; return NULL; }' in plugin
assert 'if (!orig_dlopen) { errno = ENOENT; return NULL; }' in plugin
assert 'orig_dlopen("/.bds_blocked_nonexistent"' not in plugin
assert '[NSThread isMainThread]' in function(plugin,'bds_dyld_add_image_cb')
assert 'g_bdsRebindFailures++' in plugin
# ---- 9.30-10：屏幕参数同步到百度侧出口（只改 B 层，UIScreen 保持真机）----
assert 'static NSDictionary *BDSBaiduScreenSyncValues(NSDictionary *device)' in plugin
assert 'static NSDictionary *BDSBaiduScreenSyncValues(NSDictionary *device)' in manager
# 插件侧：基础参数生成时同步
assert 'BDSBaiduScreenSyncValues(device)' in function(plugin,'BDSRandomBaseValuesForPair')
assert 'BDSBaiduScreenSyncValues(g_lastBasicDevice)' in function(plugin,'randomizeBasicProfile')
# 屏幕参数必须与“定向指纹”总开关解耦：它的值由一键基础按机型写入，
# 若仍要求 spoofBaiduTargeted 同时开启，用户没开定向时屏幕会停在真机值，
# 出现“机型已是 iPhone 13、屏幕还是 SE2”的不一致（9.30-05 实测如此）。
assert 'static BOOL tg_screen_enabled(void)' in plugin
assert 'return cfgBool(@"spoofBaiduTargetedScreen", NO);' in plugin
assert 'tg_feature_enabled(@"spoofBaiduTargetedScreen")' not in plugin
assert plugin.count('tg_screen_enabled()') >= 4
# 9.30-10：防越狱检测默认关闭，且一键基础不得打开它（索引逻辑要跳过 off 项）
assert 'static NSArray<NSString *> *BDSFirstEnabledKeys' in policy
assert 'BDSFirstEnabledKeys(groups[1], 3)' in plugin
assert 'BDSFirstEnabledKeys(groups[1], 3)' in manager
assert 'if([item[@"off"] boolValue]) continue;' in policy
# 一键基础打开的定向屏幕开关之后，防越狱检测必须是关的
assert 'merged[@"bypassJailbreakDetect"] = @NO;' in plugin
# 9.30-10：UA 的 CPU 段系统号要跟随配置值（未开自定义/定向 UA 时也要改）
assert 'static NSString *tg_rewrite_ua_cpu_only(NSString *ua)' in plugin
assert 'tg_rewrite_ua_cpu_only(ua)' in plugin
# 9.30-10：UA 改写必须带诊断（记录实际分支与实际输入输出），
# 否则“代码看起来该生效、真机上却没变”只能靠推断。
assert 'NSDictionary *BDSpooferUADebugSnapshot(void)' in plugin
assert 'tg_ua_debug_set(@"A. 输入 userAgent", ua);' in plugin
assert 'tg_ua_debug_set(@"B. 输入 userAgent", ua);' in plugin
# 机型/系统/UA/Push 仍必须受定向总开关约束，不能被一起解耦
for child in ['spoofBaiduTargetedSystem','spoofBaiduTargetedModel',
              'spoofBaiduTargetedUA','spoofBaiduTargetedPush']:
    assert 'tg_feature_enabled(@"%s")' % child in plugin, child
# 关键回归：屏幕同步必须写在开关组循环之后。
# spoofBaiduTargetedScreen 落在 groups[1] 的 i>=3 档，会被那个 @NO 循环覆盖，
# 所以同步位置必须晚于最后一处 groups[1]/groups[2] 循环（9.30-10 首版就栽在这里）。
def assert_screen_sync_after_switch_loops(text,name):
    body=function(text,name)
    stripped=re.sub(r'//[^\n]*|/\*[\s\S]*?\*/',lambda m:' '*len(m.group(0)),body)
    last_loop=max(stripped.rfind('groups[1]'),stripped.rfind('groups[2]'))
    sync=body.rfind('BDSBaiduScreenSyncValues')
    assert last_loop>=0 and sync>last_loop, (name,last_loop,sync)
assert_screen_sync_after_switch_loops(plugin,'randomizeBasicProfile')
assert_screen_sync_after_switch_loops(manager,'BDSCreateConfigForDevice')
# 卍解侧：一键基础时同步
assert 'BDSBaiduScreenSyncValues(device)' in manager
# 9.30-10：UA 的 CPU 段由 tg_rewrite_ua 改写，读的是 targetedUASystemVersion。
# 这个键一键基础从来没写过，停在模板默认值 15.4.1，于是 UA 里出现与配置无关的系统号。
assert 'static NSDictionary *BDSBaiduSystemSyncValues(NSDictionary *system)' in plugin
assert 'static NSDictionary *BDSBaiduSystemSyncValues(NSDictionary *system)' in manager
assert 'BDSBaiduSystemSyncValues(system)' in function(plugin,'BDSRandomBaseValuesForPair')
assert 'BDSBaiduSystemSyncValues(system)' in manager
assert 'BDSBaiduSystemSyncValues(g_lastBasicSystem)' in function(plugin,'randomizeBasicProfile')
for key in ['@"targetedSystemVersion"','@"targetedUASystemVersion"',
            '@"targetedSystemBuild"','@"targetedUASystemBuild"']:
    assert key in plugin,key
    assert key in manager,key
# 同步的必须是这几个键 + 只打开定向屏幕这一个子开关
for key in ['@"targetedScreenWidth"','@"targetedScreenHeight"','@"targetedScreenScale"',
            '@"targetedNativeScreenWidth"','@"targetedNativeScreenHeight"',
            '@"spoofBaiduTargetedScreen": @YES','@"spoofBaiduTargetedUA": @YES']:
    assert key in plugin,key
    assert key in manager,key
# UIScreen 钩子必须仍然只在 spoofScreen 打开时安装（保持真机，界面不错版）
assert 'if (basicEnabled && cfgBool(@"spoofScreen", NO)) {' in plugin
# 定向的机型/系统/UA 子开关不许被屏幕同步顺带打开
sync=function(plugin,'BDSBaiduScreenSyncValues')
for bad in ['spoofBaiduTargetedModel','spoofBaiduTargetedSystem',
            'spoofBaiduTargetedPush','spoofBaiduTargeted"']:
    assert bad not in sync, bad
print('PASS UI1.3 9.30-10: v188, 20 on / 6 off, runtime switch honored by the cash blocker, X/M advanced-random parity, SE2 out of the random pool, boundary-matched dlopen paths, measured C-hook self-check, 9 baseline jailbreak functions unchanged')
