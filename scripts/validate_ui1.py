from pathlib import Path
import plistlib,re,subprocess
root=Path(__file__).resolve().parents[1]
plugin=(root/'BDSpoofer.m').read_text(encoding='utf-8')
manager=(root/'CraneManager/BDSCraneManager.m').read_text(encoding='utf-8')
policy=(root/'Shared/BDSConfigPolicy.h').read_text(encoding='utf-8')
config=plistlib.loads((root/'bdspoofer_config.plist').read_bytes())
items=re.findall(r'@\{@"key":@"([^"]+)",@"name":@"[^"]+"(,@"off":@YES)?\}',policy)
assert len(items)==25
regular=[key for key,off in items if not off];risk=[key for key,off in items if off]
assert len(regular)==21 and len(risk)==4
assert all(config[k] is True for k in regular)
assert all(config[k] is False for k in risk)
assert config['spoofScreen'] is False and config['configVersion']==186
assert all(config['spoofBaiduTargeted'+x] is False for x in ['', 'System','Model','Screen','UA','Push'])
for text in ['一键随机整套基础参数','一键随机整套高级参数','一键随机定向指纹参数','反关联设置','恢复安全']:assert text in plugin,text
for text in ['一键随机基础整套设置','一键随机高级整套设置','一键随机定向指纹设置','反关联设置','恢复安全']:assert text in manager,text
assert 'g_rewardProbe' not in plugin
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
base=subprocess.check_output(['git','show','b65d42ab33948455ef84e57d109d0dbede2a1b72:BDSpoofer.m'],cwd=root).decode('utf-8')
names=['bds_c_is_jailbreak_path','bds_is_suspicious_dlopen_path','bds_my_dlopen','bds_my_dlopen_preflight','bds_my_stat','bds_my_lstat','bds_my_access','bds_my_fopen','bds_my_opendir','bds_perform_rebinding_with_section','bds_rebind_symbols_for_image']
for name in names:assert function(plugin,name)==function(base,name),name
for path in ['bdspoofer_config.plist','CraneManager/Info.plist','CraneManager/BDSCraneManager.entitlements','CraneManager/BDSCraneManager.libSandy.plist']:plistlib.loads((root/path).read_bytes())
assert plistlib.loads((root/'CraneManager/Info.plist').read_bytes())['CFBundleVersion']=='103'
print('PASS UI1: 21 on / 4 off defaults, independent screen store, UI labels, plist validation, 11 baseline jailbreak functions unchanged')
