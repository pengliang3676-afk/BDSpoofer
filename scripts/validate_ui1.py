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
assert all(config[k] is True for k in regular)
assert all(config[k] is False for k in risk)
assert config['spoofScreen'] is False and config['configVersion']==187
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
assert 'page.title=@"卐解 1.8.1 UI1.2 9.22-01"' in plugin
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
assert 'BDSpoofer_1.8.1_UI1.2_9.22-01.dylib' in build and 'UI1.1.dylib' not in build
assert 'BDSpooferCraneManager_1.0.2-ui1_9.22-01_RootHide.deb' in build
assert 'self.title = @"卍解 1.0.2 9.22-01"' in manager
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
names=['bds_c_is_jailbreak_path','bds_is_suspicious_dlopen_path','bds_my_dlopen','bds_my_dlopen_preflight','bds_my_stat','bds_my_lstat','bds_my_access','bds_my_fopen','bds_my_opendir','bds_perform_rebinding_with_section','bds_rebind_symbols_for_image']
for name in names:assert function(plugin,name)==function(base,name),name
for path in ['bdspoofer_config.plist','CraneManager/Info.plist','CraneManager/BDSCraneManager.entitlements','CraneManager/BDSCraneManager.libSandy.plist']:plistlib.loads((root/path).read_bytes())
manager_info=plistlib.loads((root/'CraneManager/Info.plist').read_bytes())
assert manager_info['CFBundleVersion']=='9.22.01' and manager_info['CFBundleShortVersionString']=='1.0.2-9.22.01'
assert 'UIApplicationExitsOnSuspend' not in manager_info
print('PASS UI1.2: v187, 21 on / 5 off, exact telemetry block, 37 synchronized devices, UI1.2 package names, 11 baseline jailbreak functions unchanged')
