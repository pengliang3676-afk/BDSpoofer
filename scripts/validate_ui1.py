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
assert len(regular)==21 and len(risk)==5
basic_keys=['enabled','spoofAdvertisingIdentifiers','spoofProcessHardware','spoofLocale','spoofCarrier','spoofStorage']
assert all(config[k] is False for k in basic_keys)
assert all(config[k] is True for k in regular if k not in basic_keys)
assert all(config[k] is False for k in risk)
advanced_keys=['spoofBaiduSDK','spoofSysctl','bypassJailbreakDetect','spoofKeychain','spoofAppGroup','spoofWebKitCookie','spoofUserAgent']
advanced_on=advanced_keys[:3]
advanced_off=advanced_keys[3:]
assert all(key in regular and config[key] is True for key in advanced_on)
assert all(key in risk and config[key] is False for key in advanced_off)
targeted_keys=['spoofBaiduTargeted','spoofBaiduTargetedSystem','spoofBaiduTargetedModel','spoofBaiduTargetedScreen','spoofBaiduTargetedUA','spoofBaiduTargetedPush']
default_block=plugin.split('static NSDictionary *BDSDefaultConfig(void)',1)[1].split('static void bds_update_c_cache(void)',1)[0]
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@YES',default_block) for key in advanced_on)
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@NO',default_block) for key in advanced_off)
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@NO',default_block) for key in targeted_keys)
assert all(re.search(r'@"'+re.escape(key)+r'"\s*:\s*@NO',default_block) for key in basic_keys)
assert config['spoofScreen'] is False and config['configVersion']==188
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
load_start=plugin.index('static void loadConfig()')
load_end=plugin.index('static BOOL saveConfigValues',load_start)
load_body=plugin[load_start:load_end]
assert 'BOOL hasPersistentConfig' in load_body and 'if (!hasPersistentConfig)' in load_body
assert load_body.index('return;') < load_body.index('NSInteger ver =')
assert 'page.title=@"卐解 1.8.2 UI1.2"' in plugin
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
sparse.update(managerContainerIdentifier='12345678-1234-1234-1234-123456789012',managerGeneratedAt=1.0,managerProfileVersion=104,managerRandomMode='basic',didRandomizeBasic=True)
assert len(plistlib.dumps(sparse,fmt=plistlib.FMT_XML,sort_keys=False))<4096
assert 'g_rewardProbe' not in plugin
assert 'BDSInstallCashSpoofing' not in plugin and 'arc4random_uniform(101)' not in plugin
assert 'dataTaskWithRequest' not in blocker and 'willPerformHTTPRedirection' not in blocker
for text in ['h2tcbox.baidu.com','/ztbox','zpblog','10290','y_mission_index','c_pv','ext[@"num"]']:
    assert text in blocker,text
assert 'BDSInstallCashTelemetryBlocking();' in plugin
assert plugin.count('loadConfig();') >= 3
assert '0.50' not in release and '触发风控' not in release
assert 'BDSpoofer_1.8.2_UI1.2.dylib' in build and 'BDSpoofer_1.8.1_UI1.2.dylib' not in build
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
plugin_systems=re.findall(r'BDSSystem\(@"([^"]+)",\s*@"([^"]+)"\)',function(plugin,'BDSSystemProfiles'))
manager_systems=re.findall(r'BDSSystem\(@"([^"]+)",\s*@"([^"]+)"\)',function(manager,'BDSSystemProfiles'))
assert plugin_systems==manager_systems and len(plugin_systems)>50
base=subprocess.check_output(['git','show','b65d42ab33948455ef84e57d109d0dbede2a1b72:BDSpoofer.m'],cwd=root).decode('utf-8')
names=['bds_c_is_jailbreak_path','bds_is_suspicious_dlopen_path','bds_my_dlopen','bds_my_dlopen_preflight','bds_my_stat','bds_my_lstat','bds_my_access','bds_my_fopen','bds_my_opendir','bds_perform_rebinding_with_section','bds_rebind_symbols_for_image']
for name in names:assert function(plugin,name)==function(base,name),name
for path in ['bdspoofer_config.plist','CraneManager/Info.plist','CraneManager/BDSCraneManager.entitlements','CraneManager/BDSCraneManager.libSandy.plist']:plistlib.loads((root/path).read_bytes())
manager_info=plistlib.loads((root/'CraneManager/Info.plist').read_bytes())
assert manager_info['CFBundleShortVersionString']=='1.0.3' and manager_info['CFBundleVersion']=='104' and 'UIApplicationExitsOnSuspend' not in manager_info
print('PASS 1.8.2 UI1.2 / manager 1.0.3: v188, targeted defaults off and one-click enables all 5, advanced first 3 default on and last 4 default off, 36 synchronized devices')
