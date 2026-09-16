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
test_sources=[
    (root/'tests/PluginConfigTests.m').read_text(encoding='utf-8'),
    (root/'tests/ManagerConfigTests.m').read_text(encoding='utf-8'),
]
items=re.findall(r'@\{@"key":@"([^"]+)",@"name":@"[^"]+"(,@"off":@YES)?\}',policy)
assert len(items)==26
regular=[key for key,off in items if not off];risk=[key for key,off in items if off]
assert len(regular)==21 and len(risk)==5
basic_keys=['enabled','spoofAdvertisingIdentifiers','spoofProcessHardware','spoofSysctl','spoofLocale','spoofCarrier','spoofStorage']
# 总开关默认关闭（新容器=真机参数），其余 6 个基础子开关默认开
assert config['enabled'] is False
assert all(config[k] is True for k in basic_keys if k!='enabled')
assert all(config[k] is True for k in regular if k not in basic_keys)
assert all(config[k] is False for k in risk)
advanced_keys=['spoofBaiduSDK','bypassJailbreakDetect','spoofKeychain','spoofAppGroup','spoofWebKitCookie','spoofUserAgent']
advanced_on=advanced_keys[:2]
advanced_off=advanced_keys[2:]
assert all(key in regular and config[key] is True for key in advanced_on)
assert all(key in risk and config[key] is False for key in advanced_off)
targeted_keys=['spoofBaiduTargeted','spoofBaiduTargetedSystem','spoofBaiduTargetedModel','spoofBaiduTargetedScreen','spoofBaiduTargetedUA','spoofBaiduTargetedPush']
default_block=plugin.split('static NSDictionary *BDSDefaultConfig(void)',1)[1].split('static void bds_update_c_cache(void)',1)[0]
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@YES',default_block) for key in advanced_on)
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@NO',default_block) for key in advanced_off)
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@NO',default_block) for key in targeted_keys)
assert re.search(r'@"enabled"\s*:\s*@NO',default_block)
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@YES',default_block) for key in basic_keys if key!='enabled')
assert config['spoofScreen'] is False and config['configVersion']==189
for test_source in test_sources:
    assert 'config[@"configVersion"] integerValue]==189' in test_source
    assert 'assert(![config[@"enabled"] boolValue])' in test_source
    assert 'if(![key isEqualToString:@"enabled"])' in test_source
assert config['blockStatCashTelemetry'] is False
assert 'blockStatCashTelemetry' in policy and 'blockStatCashTelemetry' in plugin
assert '金额上报：%@' in plugin and '? @"已开启" : @"已关闭"' in plugin
assert all(config['spoofBaiduTargeted'+x] is False for x in ['', 'System','Model','Screen','UA','Push'])
for text in ['一键随机整套基础参数','一键随机整套高级参数','一键随机定向指纹参数','反关联项','诊断自检','恢复安全']:assert text in plugin,text
for text in ['一键随机基础整套设置','一键随机高级整套设置','一键随机定向指纹设置','反关联项','恢复安全']:assert text in manager,text
for text in ['基础功能：当前功能状态  %@','高级功能：%@','定向指纹：%@','反关联项：%@','尚未执行一键随机']:
    assert text in plugin,text
assert '反关联增强：%@' not in plugin and '收益额上报：%@' not in plugin
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
assert 'BDSContainerHasDefaultMarker' in manager and 'configuredDefaultID ?: systemDefaultID ?: actuallyActiveID' in manager
assert 'containerID.uppercaseString isEqualToString:@"DEFAULT"' in manager
assert 'displayCurrentContainerID' in manager and 'self.activeContainerID' not in manager
reload_start=manager.index('- (void)reloadContainers')
reload_end=manager.index('- (NSInteger)tableView:',reload_start)
reload_body=manager[reload_start:reload_end]
assert 'BDSWriteContainerConfig' not in reload_body and 'BDSMergedConfig' not in reload_body
assert 'NSString *summary = BDSContainerSummary(config);' in reload_body
assert 'selectedContainersHaveConfig' in manager and '请先对选中容器执行一次一键随机' in manager
# 反关联页不再要求先选容器/先随机：showAssociationSettings 内不得有拦截，缺配置走完整模板打底
assoc_start=manager.index('- (void)showAssociationSettings')
assoc_end=manager.index('- (void)restoreSafeSettings',assoc_start)
assoc_body=manager[assoc_start:assoc_end]
assert 'selectedContainersHaveConfig' not in assoc_body and 'showMessage' not in assoc_body
assert 'switchBaseForMissingConfig' in manager and 'BDSAssociationSwitchDraft' in manager
assert 'contextFooter' in (root/'Shared/BDSSettingsUI.h').read_text(encoding='utf-8')
load_start=plugin.index('static void loadConfig()')
load_end=plugin.index('static BOOL saveConfigValues',load_start)
load_body=plugin[load_start:load_end]
assert 'BOOL hasPersistentConfig' in load_body and 'if (!hasPersistentConfig)' in load_body
assert load_body.index('return;') < load_body.index('NSInteger ver =')
assert 'BDSApplyInitialDefaults(merged, merged);' in load_body
assert 'BDSApplyInitialDefaults(merged, loaded);' not in load_body.split('NSInteger ver =',1)[1]
assert '@selector(requestAccessToEntityType:completion:)' in plugin
assert plugin.count('@selector(requestAccessForEntityType:completionHandler:)')==1
assert 'page.title=@"卐解 9.15-03"' in plugin
# H5 网页层一致性：导航入口挂 DocumentStart 脚本（9.15-03 起不再用初始化器注入）
assert 'bds_webCoherenceScript' in plugin and 'bds_armWebCoherence' in plugin
assert "@selector(loadRequest:)" in plugin and "@selector(loadHTMLString:baseURL:)" in plugin
assert 'initWithFrame:configuration:' not in plugin
# 9.15-02：XHR/fetch/sendBeacon 出站 ua= 分辨率改写必须存在
assert 'XMLHttpRequest.prototype.open' in plugin and 'window.fetch' in plugin and 'navigator.sendBeacon' in plugin
assert '定向总开关及 5 个子开关已全部开启' in plugin
assert 'selectedTargetedKeys = [NSSet setWithArray:BDSTargetedKeys()]' in manager
assert '执行一键随机后自动开启全部 5 项' in (root/'Shared/BDSSettingsUI.h').read_text(encoding='utf-8')
assert 'didRandomize%@%@' in policy
for text in ['BDSMarkRandomModeRun','BDSRandomModeWasRun','BDSConfigForPersistentStorage']:
    assert text in plugin+manager+policy,text
assert 'BDSCleanContainerDisplayName' in manager and '（默认）' in manager
assert 'numberOfLines = 3' in manager and 'sideInset=18.0' in manager
targeted_values=['targetedDeviceProfileName','targetedSystemVersion','targetedSystemBuild','targetedHwMachine','targetedHwModel','targetedScreenHwMachine','targetedScreenWidth','targetedScreenHeight','targetedScreenScale','targetedNativeScreenWidth','targetedNativeScreenHeight','targetedUASystemVersion','targetedUASystemBuild','targetedPushDeviceProfileName','targetedPushHwMachine','targetedPushHwModel','targetedGeneratedAt']
sparse=dict(config)
for key in targeted_values:sparse.pop(key,None)
sparse.pop('managerResolvedPath',None)
sparse.update(managerContainerIdentifier='12345678-1234-1234-1234-123456789012',managerGeneratedAt=1.0,managerProfileVersion=107,managerRandomMode='basic',didRandomizeBasic=True)
assert len(plistlib.dumps(sparse,fmt=plistlib.FMT_XML,sort_keys=False))<4096
assert 'g_rewardProbe' not in plugin
assert 'BDSInstallCashSpoofing' not in plugin and 'arc4random_uniform(101)' not in plugin
assert 'dataTaskWithRequest' not in blocker and 'willPerformHTTPRedirection' not in blocker
for text in ['h2tcbox.baidu.com','/ztbox','zpblog','10290','y_mission_index','c_pv','ext[@"num"]']:
    assert text in blocker,text
assert 'BDSInstallCashTelemetryBlocking();' in plugin
assert plugin.count('loadConfig();') >= 3
assert '0.50' not in release and '触发风控' not in release
assert 'BDSpoofer_9.15-03.dylib' in build and 'BDSpoofer_9.15-02.dylib' not in build
assert '[verified isEqualToDictionary:config]' in manager
assert 'targetedScreenHwMachine' in plugin and 'targetedScreenHwMachine' in manager
def function(text,name):
    match=re.search(r'^static [^\n]*\b'+name+r'\(',text,re.M);assert match,name
    pos=text.index('{',match.start())
    stripped=re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m[0]),text)
    depth=0
    for i in range(pos,len(text)):
        depth+=(stripped[i]=='{')-(stripped[i]=='}')
        if depth==0:return text[match.start():i+1]
    raise AssertionError(name)
targeted_random=function(plugin,'BDSRandomTargetedProfileValues')
for key in targeted_keys:
    assert re.search(r'@"'+re.escape(key)+r'"\s*:\s*@YES',targeted_random),key
assert 'cfgBool(' not in targeted_random
manager_random=function(manager,'BDSCreateRandomConfig')
assert 'selectedTargetedKeys = [NSSet setWithArray:BDSTargetedKeys()]' in manager_random
# B 方案：基础随机三层一致（管理器+插件），残留隔离四项自动开
assert 'BDSCoherentTargetedValues' in manager and 'BDSCoherentAdvancedSwitches' in manager
# 剥掉单行前置声明，避免函数提取器把声明当成定义
plugin_nd=re.sub(r'^static [^\n;]*;\s*$','',plugin,flags=re.M)
manager_nd=re.sub(r'^static [^\n;]*;\s*$','',manager,flags=re.M)
mgr_dev=function(manager_nd,'BDSCreateConfigForDevice')
assert 'BDSCoherentTargetedValues(device, system)' in mgr_dev and 'BDSCoherentAdvancedSwitches()' in mgr_dev
assert 'BDSCoherentTargetedValuesForPair' in plugin and 'BDSCoherentAdvancedSwitchValues' in plugin
assert 'BDSCoherentTargetedValuesForPair(device, system)' in function(plugin_nd,'BDSRandomBaseValuesForPair')
assert 'BDSCoherentTargetedValuesForPair(device, system)' in function(plugin_nd,'BDSProfileApplyValues')
for coherent in [function(manager_nd,'BDSCoherentTargetedValues'), function(plugin_nd,'BDSCoherentTargetedValuesForPair')]:
    for key in targeted_keys:
        assert re.search(r'@"'+re.escape(key)+r'"\s*:\s*@YES',coherent),key
    for token in ['device[@"machine"]','system[@"version"]','device[@"width"]']:
        assert token in coherent,token
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
        if machine=='iPhone12,8': continue
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
assert len(plugin_pool)==36 and plugin_pool==manager_pool
# 默认模板必须是机型池内真实存在的一套自洽组合（iPhone 17 Pro Max），基础段与定向段一致
default_machine='iPhone18,2'
assert default_machine in plugin_pool
_name,_model,w,h,nw,nh,scale,memory,disks=plugin_pool[default_machine]
assert (_name,_model,w,h,nw,nh,scale,memory)==('iPhone 17 Pro Max','V54AP',440,956,1320,2868,3,12288)
assert 256 in disks
basic_expect={'deviceProfileName':'iPhone 17 Pro Max','systemVersion':'26.6','systemBuild':'23G71',
    'kernOSVersion':'23G71','hwMachine':'iPhone18,2','hwModel':'V54AP'}
for k,v in basic_expect.items():
    assert config[k]==v,(k,config[k])
assert (config['memorySize'],config['diskSize'],config['screenWidth'],config['screenHeight'],
        config['screenScale'],config['nativeScreenWidth'],config['nativeScreenHeight'])==(12288,256,440,956,3,1320,2868)
for suffix,val in [('DeviceProfileName','iPhone 17 Pro Max'),('SystemVersion','26.6'),('SystemBuild','23G71'),
                   ('HwMachine','iPhone18,2'),('HwModel','V54AP'),('UASystemVersion','26.6'),
                   ('UASystemBuild','23G71'),('PushDeviceProfileName','iPhone 17 Pro Max'),
                   ('PushHwMachine','iPhone18,2'),('PushHwModel','V54AP'),('ScreenHwMachine','iPhone18,2')]:
    assert config['targeted'+suffix]==val,suffix
assert (config['targetedScreenWidth'],config['targetedScreenHeight'],config['targetedScreenScale'],
        config['targetedNativeScreenWidth'],config['targetedNativeScreenHeight'])==(440,956,3,1320,2868)
for lit in ['@"iPhone18,2"','@"V54AP"','@"26.6"','@"23G71"','@440','@956','@3','@1320','@2868','@12288','@256']:
    assert lit in default_block,lit
plugin_systems=re.findall(r'BDSSystem\(@"([^"]+)",\s*@"([^"]+)"\)',function(plugin,'BDSSystemProfiles'))
manager_systems=re.findall(r'BDSSystem\(@"([^"]+)",\s*@"([^"]+)"\)',function(manager,'BDSSystemProfiles'))
assert plugin_systems==manager_systems and len(plugin_systems)>50
base=subprocess.check_output(['git','show','b65d42ab33948455ef84e57d109d0dbede2a1b72:BDSpoofer.m'],cwd=root).decode('utf-8')
names=['bds_c_is_jailbreak_path','bds_is_suspicious_dlopen_path','bds_my_dlopen','bds_my_dlopen_preflight','bds_my_stat','bds_my_lstat','bds_my_access','bds_my_fopen','bds_my_opendir','bds_perform_rebinding_with_section','bds_rebind_symbols_for_image']
for name in names:assert function(plugin,name)==function(base,name),name
for path in ['bdspoofer_config.plist','CraneManager/Info.plist','CraneManager/BDSCraneManager.entitlements','CraneManager/BDSCraneManager.libSandy.plist']:plistlib.loads((root/path).read_bytes())
manager_info=plistlib.loads((root/'CraneManager/Info.plist').read_bytes())
assert manager_info['CFBundleShortVersionString']=='9.15.3' and manager_info['CFBundleVersion']=='107' and 'UIApplicationExitsOnSuspend' not in manager_info
print('PASS 9.15-03 / manager 9.15.3(107): v189, H5 coherence script armed at navigation entry, outbound ua= rewrite (XHR/fetch/sendBeacon) outermost, master enabled default OFF, other 6 basic switches default on, advanced first 2 default on, default preset iPhone 17 Pro Max, 36 synchronized devices')
