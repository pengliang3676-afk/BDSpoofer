//
//  BDDiag3.m —— 百度极速版「短信登录」设备字段 发现型只读探针 v1
//
//  目标：找出短信登录请求里“设备型号/机型”到底由哪个类的哪个方法提供，解释账号设备记录为何显示“未知设备”。
//  与 BDDiag2 的区别：BDDiag2 是固定 17 个已知方法；BDDiag3 按【类名关键词 + 方法名关键词】在运行时
//  动态发现候选方法并只读挂接，配合“采集窗口”只记录你走短信登录那段时间的调用。
//
//  安全原则（沿用 BDDiag2 v4 已复审的骨架）：
//   1. 只挂【返回对象 @、0~2 个对象参数】的方法；结构体/标量/复杂参数/init/setter 一律不挂；
//   2. 永远先调原实现、原值原样返回，本探针不改任何返回值；
//   3. 只有处于“采集窗口”内才计数/采样，每个方法只采 1 次返回样本+短栈，之后仅计数；
//   4. _Thread_local 递归抑制；继承方法先 class_addMethod 落地本类再交换，不改父类；
//   5. 类可能晚加载：启动后短时重试，且每次点“开始采集”会再扫一遍类列表；
//   6. 手机号/UUID/token 脱敏，NSString 最多 300 字，NSData 只记长度，其余对象只记类名。
//
//  操作：注入后浮窗点“开始采集”→ 去走一遍短信登录（输手机号、收验证码、点登录到请求发出）→ 点“导出”。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <execinfo.h>
#import <os/lock.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <ctype.h>
#import <math.h>
#import <stdatomic.h>
#import <string.h>

// ============================== 全局状态 ==============================
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static os_unfair_lock g_installLock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSMutableDictionary *> *g_records = nil;       // 所有已挂方法
static NSMutableDictionary<NSString *, NSMutableArray *> *g_bySel = nil; // selName -> records
static _Thread_local int t_suppress = 0;
static uintptr_t g_ownLow = 0, g_ownHigh = 0;
static int g_methodIndex = 0;     // alias selector 唯一序号
static _Atomic(int) g_hookedCount = 0;     // 已成功挂接数
static _Atomic(BOOL) g_capturing = NO;
static _Atomic(unsigned) g_captureGeneration = 0;
static _Atomic(unsigned) g_scanCycle = 0;
static _Atomic(BOOL) g_capReached = NO;
static _Atomic(BOOL) g_dyldDiscoverPending = NO;
static dispatch_group_t g_sampleGroup = nil;
static NSTimeInterval g_startAt = 0;
static const int kMaxHook = 600;
static UILabel *g_statusLabel = nil;

static BOOL b3_inSelf(uintptr_t p){ return p>=g_ownLow && p<g_ownHigh; }

static char b3_typeKind(const char *enc) {
    if (!enc) return '?';
    while (*enc) {
        char c=*enc;
        if (isdigit(c)||c=='r'||c=='n'||c=='N'||c=='o'||c=='O'||c=='R'||c=='V'){enc++;continue;}
        return c;
    }
    return '?';
}

// ============================== 类名 / 方法名 匹配规则 ==============================
static NSInteger b3_classPriority(NSString *name) {
    if (!name.length) return NO;
    NSString *x = name.lowercaseString;
    NSArray *exact = @[@"uidevice",@"basicdeviceinfo",@"deviceinfo",@"sdeviceinfo",
                       @"hdeviceinfomxxtiy",@"hphoneinfoholdermxxtiy",@"jdeviceutils",
                       @"devicehelper",@"managerpassport"];
    if ([exact containsObject:x]) return 3;
    // 只排除明确的 UI 类；不能用笼统的 "view"，否则 LoginViewModel 会被误杀。
    NSArray *block = @[@"viewcontroller",@"controller",@"cell",@"layer",@"animation",@"gesture",@"button",
                       @"label",@"imageview",@"textfield",@"textview",@"layout",@"canvas",@"draw",@"render",@"widget",@"panel"];
    for (NSString *b in block) if ([x containsString:b]) return 0;
    if ([x hasSuffix:@"view"] && ![x hasSuffix:@"viewmodel"]) return 0;
    NSArray *critical = @[@"passport",@"quicklogin",@"onelogin",@"smslogin",@"mobileauth",
                          @"carrierlogin",@"loginsession",@"accountlogin",@"loginmanager",
                          @"loginservice",@"loginauth",@"bdlogin",@"bplogin"];
    for (NSString *k in critical) if ([x containsString:k]) return 2;
    NSArray *keys = @[@"deviceinfo",@"deviceutil",@"devicehelper",@"basicdevice",@"sdevice",
                      @"hdevice",@"jdevice",@"phonedevice",@"devicemanager",@"hardware",
                      @"talos",@"platforminfo",@"dmdevice",
                      @"bdpdevice",@"baidumobstatdevice",@"terminalinfo",@"phoneinfo",
                      @"deviceparameter",@"devicemetrics",@"systeminfo"];
    for (NSString *k in keys) if ([x containsString:k]) return 1;
    return 0;
}
static BOOL b3_classMatch(NSString *name) {
    return b3_classPriority(name) > 0;
}
static BOOL b3_selMatch(NSString *clsName, NSString *sel) {
    if (!sel.length || sel.length > 64) return NO;
    NSString *x = sel.lowercaseString;
    if ([x hasPrefix:@"set"]) return NO;                    // setter 是写操作，不挂
    // UIDevice 关键取值方法白名单（name 本身太短，单独放行）
    if ([clsName isEqualToString:@"UIDevice"] &&
        [@[@"name",@"model",@"localizedmodel",@"systemversion",@"systemname",@"identifierforvendor"] containsObject:x])
        return YES;
    NSArray *block = @[@"viewmodel",@"datamodel",@"mlmodel",@"3dmodel",@"modelview",@"cellmodel",
                       @"itemmodel",@"sectionmodel",@"rowmodel",@"listmodel",@"businessmodel",
                       @"modeltransform",@"modelclass",@"modellayer",@"entitymodel",@"ttsmodel",
                       @"speechmodel",@"vad",@"downloadmodel",@"modelmanager",
                       @"format",@"arguments",@"valist"];
    for (NSString *b in block) if ([x containsString:b]) return NO;
    NSArray *keys = @[@"model",@"machine",@"brand",@"product",@"terminal",@"platform",
                      @"marketing",@"useragent",@"systemversion",@"osversion",@"sysversion",
                      @"identifier",@"cuid",@"utdid",@"deviceid",@"phonetype",@"handset",
                      @"devicename",@"phonename",@"machinename",@"modelname",@"hostname",
                      @"clienttype",@"ostype",@"devicetype",@"phonemodel",@"devicemodel",
                      @"hardware",@"vendor"];
    for (NSString *k in keys) if ([x containsString:k]) return YES;
    return NO;
}

// ============================== 脱敏 ==============================
static NSRegularExpression *g_phoneRx=nil,*g_uuidRx=nil,*g_tokenRx=nil;
static void b3_ensureRx(void){ static dispatch_once_t t; dispatch_once(&t,^{
    g_phoneRx=[NSRegularExpression regularExpressionWithPattern:@"1[3-9]\\d{9}" options:0 error:nil];
    g_uuidRx =[NSRegularExpression regularExpressionWithPattern:@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" options:0 error:nil];
    g_tokenRx=[NSRegularExpression regularExpressionWithPattern:@"[A-Za-z0-9_\\-]{24,}" options:0 error:nil];
});}
static BOOL b3_sensitiveKey(NSString *k){
    NSString *x=k.lowercaseString;
    NSString *c=[[[x stringByReplacingOccurrencesOfString:@"_" withString:@""]
                  stringByReplacingOccurrencesOfString:@"-" withString:@""]
                  stringByReplacingOccurrencesOfString:@" " withString:@""];
    for (NSString *b in @[@"cookie",@"token",@"session",@"pass",@"pwd",@"secret",@"account",
                          @"idfa",@"idfv",@"auth",@"ticket"]) if ([x containsString:b]) return YES;
    for (NSString *b in @[@"phonenumber",@"mobilenumber",@"msisdn"]) if ([c containsString:b]) return YES;
    return NO;
}
static NSString *b3_mask(NSString *s){
    if(!s)return nil; b3_ensureRx();
    NSString *o=[g_phoneRx stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0,s.length) withTemplate:@"1XX****XXXX"];
    o=[g_uuidRx stringByReplacingMatchesInString:o options:0 range:NSMakeRange(0,o.length) withTemplate:@"uuid***"];
    o=[g_tokenRx stringByReplacingMatchesInString:o options:0 range:NSMakeRange(0,o.length) withTemplate:@"token***"];
    if(o.length>300)o=[[o substringToIndex:300]stringByAppendingString:@"…(截断)"];
    return o;
}
static NSString *b3_summary(id v,int depth,NSString *hint){
    if(!v)return @"nil";
    Class c=[v class];
    if([v isKindOfClass:NSString.class]){
        if(hint&&b3_sensitiveKey(hint))return [NSString stringWithFormat:@"<NSString len=%lu 已脱敏>",(unsigned long)((NSString*)v).length];
        return [NSString stringWithFormat:@"NSString: %@",b3_mask((NSString*)v)];
    }
    if([v isKindOfClass:NSNumber.class])return [NSString stringWithFormat:@"%@: %@",NSStringFromClass(c),v];
    if([v isKindOfClass:NSUUID.class])return [NSString stringWithFormat:@"NSUUID: %@",b3_mask([(NSUUID*)v UUIDString])];
    if([v isKindOfClass:NSDate.class])return [NSString stringWithFormat:@"NSDate: %@",v];
    if([v isKindOfClass:NSData.class])return [NSString stringWithFormat:@"<NSData len=%lu>",(unsigned long)((NSData*)v).length];
    if([v isKindOfClass:NSURL.class])return [NSString stringWithFormat:@"NSURL: %@://%@",((NSURL*)v).scheme?:@"",((NSURL*)v).host?:@""];
    if([v isKindOfClass:NSArray.class]){
        NSArray *snap=nil;@try{snap=[[NSArray alloc]initWithArray:(NSArray*)v copyItems:NO];}@catch(NSException*e){return @"[NSArray 枚举失败]";}
        NSMutableArray *ts=[NSMutableArray array];
        for(id e in snap){if(ts.count>=8)break;[ts addObject:NSStringFromClass([e class])?:@"?"];}
        return [NSString stringWithFormat:@"[NSArray count=%lu 元素:%@]",(unsigned long)snap.count,[ts componentsJoinedByString:@","]];
    }
    if([v isKindOfClass:NSDictionary.class]){
        if(depth>1)return [NSString stringWithFormat:@"{NSDictionary count=%lu}",(unsigned long)[(NSDictionary*)v count]];
        NSDictionary *snap=nil;@try{snap=[[NSDictionary alloc]initWithDictionary:(NSDictionary*)v copyItems:NO];}@catch(NSException*e){return @"{NSDictionary 枚举失败}";}
        NSMutableArray *parts=[NSMutableArray array];int n=0;
        for(id k in snap){
            if(n++>=40){[parts addObject:@"…"];break;}
            id val=snap[k];
            NSString *ks=[k isKindOfClass:NSString.class]?(NSString*)k:NSStringFromClass([k class]);
            if(ks.length>60)ks=[[ks substringToIndex:60]stringByAppendingString:@"…"];
            NSString *vs;
            if(b3_sensitiveKey(ks))vs=[NSString stringWithFormat:@"<%@ 已脱敏>",NSStringFromClass([val class])];
            else if([val isKindOfClass:NSDictionary.class]||[val isKindOfClass:NSArray.class])vs=b3_summary(val,depth+1,ks);
            else if([val isKindOfClass:NSString.class])vs=[NSString stringWithFormat:@"NSString(值=%@)",b3_mask(val)];
            else if([val isKindOfClass:NSNumber.class])vs=[NSString stringWithFormat:@"%@(值=%@)",NSStringFromClass([val class]),val];
            else vs=NSStringFromClass([val class])?:@"?";
            [parts addObject:[NSString stringWithFormat:@"%@=%@",ks,vs]];
        }
        return [NSString stringWithFormat:@"{NSDictionary count=%lu keys:[%@]}",(unsigned long)snap.count,[parts componentsJoinedByString:@", "]];
    }
    return [NSString stringWithFormat:@"<%@>",NSStringFromClass(c)];
}
static NSString *b3_stack(void){
    void *bt[12];int n=backtrace(bt,12);NSMutableArray *a=[NSMutableArray array];
    for(int i=0;i<n&&a.count<7;i++){
        if(b3_inSelf((uintptr_t)bt[i]))continue;
        Dl_info info;memset(&info,0,sizeof(info));
        if(dladdr(bt[i],&info)){
            const char *img=info.dli_fname?strrchr(info.dli_fname,'/'):NULL;img=img?img+1:(info.dli_fname?:"?");
            uintptr_t off=(uintptr_t)bt[i]-(uintptr_t)info.dli_fbase;
            NSString *sym=info.dli_sname?[NSString stringWithUTF8String:info.dli_sname]:@"";
            [a addObject:[NSString stringWithFormat:@"    %s+0x%lx %@",img,(unsigned long)off,sym]];
        }
    }
    return [a componentsJoinedByString:@"\n"];
}

// ============================== 记录 / trampoline ==============================
static NSMutableDictionary *b3_findRec(id self,SEL _cmd,SEL *aliasOut){
    NSString *selName=NSStringFromSelector(_cmd),*aliasName=nil;NSMutableDictionary *found=nil;
    os_unfair_lock_lock(&g_lock);
    @try{
        NSArray *cands=g_bySel[selName];
        // 必须按真实派发层级从近到远匹配；不能让数组中较早的父类记录抢走子类实现。
        for(Class cursor=object_getClass(self);cursor&&!found;cursor=class_getSuperclass(cursor)){
            for(NSMutableDictionary *r in cands)if(r[@"installedClass"]==cursor){found=r;aliasName=r[@"aliasSel"];break;}
        }
    }
    @finally{os_unfair_lock_unlock(&g_lock);}
    if(aliasOut)*aliasOut=aliasName?NSSelectorFromString(aliasName):NULL;
    return found;
}
static void b3_observe(NSMutableDictionary *rec,id ret,int argc,id a0,id a1){
    if(!rec||t_suppress||!atomic_load_explicit(&g_capturing,memory_order_acquire))return;
    BOOL accepted=NO,sample=NO;NSTimeInterval rel=0;
    unsigned generation=atomic_load_explicit(&g_captureGeneration,memory_order_acquire);
    os_unfair_lock_lock(&g_lock);
    @try{
        if(atomic_load_explicit(&g_capturing,memory_order_relaxed)&&
           generation==atomic_load_explicit(&g_captureGeneration,memory_order_relaxed)){
            accepted=YES;
            rec[@"hits"]=@([rec[@"hits"]unsignedLongValue]+1);
            if(![rec[@"sampled"]boolValue]){
                rec[@"sampled"]=@YES;sample=YES;
                rel=[NSDate date].timeIntervalSince1970-g_startAt;
                dispatch_group_enter(g_sampleGroup);
            }
        }
    }@finally{os_unfair_lock_unlock(&g_lock);}
    if(!accepted||!sample)return;
    NSString *rs=nil,*st=nil;NSMutableArray<NSString*> *argSum=nil;BOOL sampleOK=YES;
    t_suppress++;
    @try{
        rs=b3_summary(ret,0,nil);
        if(argc>0){argSum=[NSMutableArray arrayWithCapacity:(NSUInteger)argc];[argSum addObject:b3_summary(a0,0,nil)?:@"nil"];}
        if(argc>1)[argSum addObject:b3_summary(a1,0,nil)?:@"nil"];
        st=b3_stack();
    }
    @catch(NSException*e){sampleOK=NO;rs=[NSString stringWithFormat:@"<采样异常:%@>",e.name];}
    @finally{t_suppress--;}
    @try{
        os_unfair_lock_lock(&g_lock);
        @try{
            if(generation==atomic_load_explicit(&g_captureGeneration,memory_order_relaxed)){
                if(!sampleOK)rec[@"sampled"]=@NO;
                rec[@"rel"]=@(rel);rec[@"sampleReturn"]=rs?:@"nil";
                if(argSum.count)rec[@"sampleArgs"]=argSum;
                rec[@"sampleStack"]=st?:@"";
            }
        }@finally{os_unfair_lock_unlock(&g_lock);}
    }@finally{dispatch_group_leave(g_sampleGroup);}
}
static id b3_call0(id s,SEL sel){return ((id(*)(id,SEL))objc_msgSend)(s,sel);}
static id b3_call1(id s,SEL sel,id a){return ((id(*)(id,SEL,id))objc_msgSend)(s,sel,a);}
static id b3_call2(id s,SEL sel,id a,id b){return ((id(*)(id,SEL,id,id))objc_msgSend)(s,sel,a,b);}
static id b3_tramp0(id self,SEL _cmd){SEL aliasSel=NULL;NSMutableDictionary*r=b3_findRec(self,_cmd,&aliasSel);if(!r||!aliasSel)return nil;id ret=b3_call0(self,aliasSel);b3_observe(r,ret,0,nil,nil);return ret;}
static id b3_tramp1(id self,SEL _cmd,id a0){SEL aliasSel=NULL;NSMutableDictionary*r=b3_findRec(self,_cmd,&aliasSel);if(!r||!aliasSel)return nil;id ret=b3_call1(self,aliasSel,a0);b3_observe(r,ret,1,a0,nil);return ret;}
static id b3_tramp2(id self,SEL _cmd,id a0,id a1){SEL aliasSel=NULL;NSMutableDictionary*r=b3_findRec(self,_cmd,&aliasSel);if(!r||!aliasSel)return nil;id ret=b3_call2(self,aliasSel,a0,a1);b3_observe(r,ret,2,a0,a1);return ret;}

// ============================== 动态发现 + 安全安装 ==============================
static BOOL b3_selectorInFamily(NSString *selName,NSString *family){
    NSUInteger i=0;while(i<selName.length&&[selName characterAtIndex:i]=='_')i++;
    if(i+family.length>selName.length)return NO;
    if(![[selName substringWithRange:NSMakeRange(i,family.length)]isEqualToString:family])return NO;
    if(i+family.length==selName.length)return YES;
    unichar next=[selName characterAtIndex:i+family.length];
    return !(next>='a'&&next<='z');
}
static BOOL b3_unsafeOwnershipFamily(NSString *selName){
    for(NSString *f in @[@"init",@"alloc",@"new",@"copy",@"mutableCopy"])
        if(b3_selectorInFamily(selName,f))return YES;
    return NO;
}
static BOOL b3_classOwnsSelector(Class cls,SEL sel){
    unsigned count=0;Method *list=class_copyMethodList(cls,&count);BOOL owns=NO;
    for(unsigned i=0;i<count;i++)if(method_getName(list[i])==sel){owns=YES;break;}
    if(list)free(list);return owns;
}
static void b3_install(Class hookCls,BOOL isClass,Method m,NSString *clsName,NSString *selName){
    os_unfair_lock_lock(&g_installLock);
    @try{
        if(atomic_load_explicit(&g_hookedCount,memory_order_relaxed)>=kMaxHook){atomic_store(&g_capReached,YES);return;}
        if(b3_unsafeOwnershipFamily(selName))return;
        const char *types=method_getTypeEncoding(m)?: "?";
        char rb[8]={0};method_getReturnType(m,rb,sizeof(rb));char rk=b3_typeKind(rb);
        unsigned na=method_getNumberOfArguments(m);int argc=(int)na-2;
        if(rk!='@'||argc<0||argc>2)return;
        BOOL argsSafe=YES;
        for(unsigned i=2;i<na;i++){char ab[16]={0};method_getArgumentType(m,i,ab,sizeof(ab));char k=b3_typeKind(ab);if(!(k=='@'||k=='#'))argsSafe=NO;}
        if(!argsSafe)return;
        NSString *key=[NSString stringWithFormat:@"%@[%@ %@]",isClass?@"+":@"-",clsName,selName];
        BOOL exists=NO;
        os_unfair_lock_lock(&g_lock);
        @try{for(NSMutableDictionary *x in g_records)if([x[@"key"]isEqualToString:key]){exists=YES;break;}}
        @finally{os_unfair_lock_unlock(&g_lock);}
        if(exists)return;

        int idx=g_methodIndex++;
        IMP tramp=(argc==0)?(IMP)b3_tramp0:(argc==1)?(IMP)b3_tramp1:(IMP)b3_tramp2;
        NSString *alias=[NSString stringWithFormat:@"bd3orig_%d%@",idx,argc==0?@"":(argc==1?@":":@"::")];
        SEL aliasSel=sel_registerName(alias.UTF8String),targetSel=NSSelectorFromString(selName);
        IMP origImp=method_getImplementation(m);
        BOOL addAlias=class_addMethod(hookCls,aliasSel,tramp,types);
        BOOL addedOwn=class_addMethod(hookCls,targetSel,origImp,types);
        if(!addAlias||(!addedOwn&&!b3_classOwnsSelector(hookCls,targetSel)))return;
        Method tm=class_getInstanceMethod(hookCls,targetSel),am=class_getInstanceMethod(hookCls,aliasSel);
        if(!tm||!am)return;

        NSMutableDictionary *r=[NSMutableDictionary dictionary];
        r[@"key"]=key;r[@"clsName"]=clsName;r[@"selName"]=selName;r[@"installedClass"]=hookCls;
        r[@"kind"]=isClass?@"+(类)":@"-(实例)";r[@"aliasSel"]=alias;r[@"encoding"]=[NSString stringWithUTF8String:types];
        r[@"hits"]=@0;r[@"sampled"]=@NO;r[@"rel"]=@9999;

        // 元数据与交换在同一把锁内发布：交换后进入 trampoline 的线程会等待并看到完整记录。
        os_unfair_lock_lock(&g_lock);
        @try{
            [g_records addObject:r];
            if(!g_bySel[selName])g_bySel[selName]=[NSMutableArray array];
            [g_bySel[selName] addObject:r];
            method_exchangeImplementations(tm,am);
            atomic_fetch_add_explicit(&g_hookedCount,1,memory_order_release);
        }@finally{os_unfair_lock_unlock(&g_lock);}
    }@finally{os_unfair_lock_unlock(&g_installLock);}
}
static void b3_scanOne(Class cls,BOOL isClass){
    if(atomic_load_explicit(&g_hookedCount,memory_order_acquire)>=kMaxHook){atomic_store(&g_capReached,YES);return;}
    const char *cn=class_getName(cls);if(!cn)return;
    NSString *clsName=[NSString stringWithUTF8String:cn];
    if(!b3_classMatch(clsName))return;
    Class target=isClass?object_getClass(cls):cls;
    unsigned int mc=0;Method *ml=class_copyMethodList(target,&mc);
    for(unsigned i=0;i<mc;i++){
        if(atomic_load_explicit(&g_hookedCount,memory_order_acquire)>=kMaxHook){atomic_store(&g_capReached,YES);break;}
        SEL s=method_getName(ml[i]);const char *sn=sel_getName(s);if(!sn)continue;
        NSString *selName=[NSString stringWithUTF8String:sn];
        if(b3_selMatch(clsName,selName))b3_install(target,isClass,ml[i],clsName,selName);
    }
    if(ml)free(ml);
}
static void b3_discover(void){
    static _Atomic(BOOL) scanning=NO;
    if(atomic_exchange_explicit(&scanning,YES,memory_order_acq_rel))return;
    @try{
        unsigned int total=0;Class *classes=objc_copyClassList(&total);
        if(classes){
            NSMutableArray<NSDictionary*> *ordered=[NSMutableArray array];
            for(unsigned i=0;i<total;i++){
                Class cls=classes[i];const char *cn=cls?class_getName(cls):NULL;if(!cn)continue;
                NSString *name=[NSString stringWithUTF8String:cn];NSInteger priority=b3_classPriority(name);
                if(priority>0)[ordered addObject:@{@"class":cls,@"name":name,@"priority":@(priority)}];
            }
            free(classes);
            [ordered sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){
                NSInteger pa=[a[@"priority"]integerValue],pb=[b[@"priority"]integerValue];
                if(pa!=pb)return pa>pb?NSOrderedAscending:NSOrderedDescending;
                return [a[@"name"]compare:b[@"name"]];
            }];
            for(NSDictionary *item in ordered){
                if(atomic_load_explicit(&g_hookedCount,memory_order_acquire)>=kMaxHook){atomic_store(&g_capReached,YES);break;}
                Class cls=item[@"class"];
                b3_scanOne(cls,NO);b3_scanOne(cls,YES);
            }
        }
    }@catch(NSException *e){}
    @finally{atomic_store_explicit(&scanning,NO,memory_order_release);}
}
static void b3_discoverCycle(unsigned cycle,int remaining){
    if(cycle!=atomic_load_explicit(&g_scanCycle,memory_order_acquire))return;
    b3_discover();
    if(remaining>1)dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        b3_discoverCycle(cycle,remaining-1);
    });
}
static void b3_startDiscoverCycle(void){
    unsigned cycle=atomic_fetch_add_explicit(&g_scanCycle,1,memory_order_acq_rel)+1;
    b3_discoverCycle(cycle,24);
}
static void b3_imageAdded(const struct mach_header *mh,intptr_t slide){
    (void)mh;(void)slide;
    if(atomic_exchange_explicit(&g_dyldDiscoverPending,YES,memory_order_acq_rel))return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.1*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        atomic_store_explicit(&g_dyldDiscoverPending,NO,memory_order_release);
        b3_discover();
    });
}

// ============================== 采集窗口 / 报告 / 浮窗 ==============================
@interface BDDiag3Store : NSObject
+(void)startCapture;+(void)stopCapture;+(void)exportReport;+(NSString*)buildReport;
@end
@interface BDDiag3Window : UIWindow @end
@implementation BDDiag3Window
-(UIView*)hitTest:(CGPoint)p withEvent:(UIEvent*)e{UIView*h=[super hitTest:p withEvent:e];return(h==self||h==self.rootViewController.view)?nil:h;}
@end
@implementation BDDiag3Store
+(void)startCapture{
    dispatch_async(dispatch_get_main_queue(),^{
        b3_startDiscoverCycle(); // 每个采集窗口都重新启动一轮晚加载补扫
        unsigned generation=0;
        os_unfair_lock_lock(&g_lock);
        @try{
            atomic_store_explicit(&g_capturing,NO,memory_order_release);
            generation=atomic_fetch_add_explicit(&g_captureGeneration,1,memory_order_acq_rel)+1;
            for(NSMutableDictionary*r in g_records){
                r[@"hits"]=@0;r[@"sampled"]=@NO;r[@"rel"]=@9999;
                [r removeObjectForKey:@"sampleReturn"];[r removeObjectForKey:@"sampleArgs"];
                [r removeObjectForKey:@"sampleStack"];
            }
            g_startAt=[NSDate date].timeIntervalSince1970;
            atomic_store_explicit(&g_capturing,YES,memory_order_release);
        }@finally{os_unfair_lock_unlock(&g_lock);}
        int hooked=atomic_load_explicit(&g_hookedCount,memory_order_acquire);
        if(g_statusLabel)g_statusLabel.text=[NSString stringWithFormat:@"采集中…已挂%d",hooked];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(120*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
            BOOL stopped=NO;
            os_unfair_lock_lock(&g_lock);
            @try{
                if(generation==atomic_load_explicit(&g_captureGeneration,memory_order_relaxed))
                    stopped=atomic_exchange_explicit(&g_capturing,NO,memory_order_acq_rel);
            }@finally{os_unfair_lock_unlock(&g_lock);}
            if(stopped&&g_statusLabel){
                int count=atomic_load_explicit(&g_hookedCount,memory_order_acquire);
                g_statusLabel.text=[NSString stringWithFormat:@"已自动停(120s) 已挂%d 点导出",count];
            }
        });
    });
}
+(void)stopCapture{
    os_unfair_lock_lock(&g_lock);
    @try{atomic_store_explicit(&g_capturing,NO,memory_order_release);}
    @finally{os_unfair_lock_unlock(&g_lock);}
    if(g_statusLabel){
        int count=atomic_load_explicit(&g_hookedCount,memory_order_acquire);
        g_statusLabel.text=[NSString stringWithFormat:@"采集结束 已挂%d 点导出",count];
    }
}
+(NSString*)buildReport{
    __block NSArray*snap=nil;
    os_unfair_lock_lock(&g_lock);
    @try{snap=[[NSArray alloc]initWithArray:g_records copyItems:YES];}
    @finally{os_unfair_lock_unlock(&g_lock);}
    NSMutableArray *hit=[NSMutableArray array],*zero=[NSMutableArray array];
    for(NSDictionary*r in snap){if([r[@"hits"]unsignedLongValue]>0)[hit addObject:r];else[zero addObject:r[@"key"]];}
    [hit sortUsingComparator:^NSComparisonResult(NSDictionary*a,NSDictionary*b){
        double da=[a[@"rel"]doubleValue],db=[b[@"rel"]doubleValue];if(fabs(da-db)<0.0001)return NSOrderedSame;return da<db?NSOrderedAscending:NSOrderedDescending;}];
    NSMutableString*s=[NSMutableString string];
    [s appendString:@"BDDiag3 短信登录 设备字段发现探针报告\n"];
    [s appendFormat:@"生成时间: %@\n",[NSDate date]];
    [s appendFormat:@"已挂候选方法: %lu 个 | 采集期命中: %lu 个 | 0命中: %lu 个 | 达到封顶: %@\n\n",
        (unsigned long)snap.count,(unsigned long)hit.count,(unsigned long)zero.count,
        atomic_load_explicit(&g_capReached,memory_order_acquire)?@"是":@"否"];
    [s appendString:@"========== 采集窗口内真正被调用的方法（按首次调用时间排序）==========\n"];
    for(NSDictionary*r in hit){
        [s appendFormat:@"%@ %@  命中%@  首次+%.2fs\n",r[@"kind"],r[@"key"],r[@"hits"],[r[@"rel"]doubleValue]];
        if(r[@"encoding"])[s appendFormat:@"  签名: %@\n",r[@"encoding"]];
        if(r[@"sampleArgs"])[s appendFormat:@"  入参: %@\n",r[@"sampleArgs"]];
        if(r[@"sampleReturn"])[s appendFormat:@"  返回: %@\n",r[@"sampleReturn"]];
        if([(NSString*)r[@"sampleStack"]length])[s appendFormat:@"  短栈:\n%@\n",r[@"sampleStack"]];
        [s appendString:@"\n"];
    }
    [s appendString:@"========== 已挂但采集期 0 命中（仅列名）==========\n"];
    [s appendFormat:@"%@\n",[zero componentsJoinedByString:@", "]];
    return s;
}
+(void)exportReport{
    [self stopCapture];
    unsigned generation=atomic_load_explicit(&g_captureGeneration,memory_order_acquire);
    dispatch_group_notify(g_sampleGroup,dispatch_get_main_queue(),^{
        if(generation!=atomic_load_explicit(&g_captureGeneration,memory_order_acquire))return;
        t_suppress++;NSString*report=nil;NSString*path=nil;NSError*e=nil;
        @try{
            report=[self buildReport];UIPasteboard.generalPasteboard.string=report;
            NSString*docs=NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES).firstObject;
            NSDateFormatter*f=[NSDateFormatter new];f.dateFormat=@"yyyy-MM-dd_HH_mm_ss_ZZZ";
            path=[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"BDDiag3_log_%@.txt",[f stringFromDate:[NSDate date]]]];
            [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&e];
        }@finally{t_suppress--;}
        NSURL*url=(!e&&path)?[NSURL fileURLWithPath:path]:nil;
        t_suppress++;@try{
            UIViewController*vc=nil;
            for(UIScene*sc in UIApplication.sharedApplication.connectedScenes)
                if([sc isKindOfClass:UIWindowScene.class]&&sc.activationState==UISceneActivationStateForegroundActive)
                    for(UIWindow*x in ((UIWindowScene*)sc).windows){if(x.rootViewController){vc=x.rootViewController;break;}}
            if(!vc)return;
            UIActivityViewController*ac=[[UIActivityViewController alloc]initWithActivityItems:url?@[url,report]:@[report]applicationActivities:nil];
            UIViewController*top=vc;while(top.presentedViewController)top=top.presentedViewController;
            ac.popoverPresentationController.sourceView=top.view;[top presentViewController:ac animated:YES completion:nil];
        }@finally{t_suppress--;}
    });
}
@end

static BDDiag3Window *g_win=nil;static int g_floatTries=0;
static void b3_float(void){
    dispatch_async(dispatch_get_main_queue(),^{
        if(g_win)return;
        UIWindowScene*scene=nil;
        for(UIScene*s in UIApplication.sharedApplication.connectedScenes)
            if([s isKindOfClass:UIWindowScene.class]&&s.activationState==UISceneActivationStateForegroundActive){scene=(UIWindowScene*)s;break;}
        if(!scene){if(++g_floatTries<=12)dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{b3_float();});return;}
        t_suppress++;
        @try{
            BDDiag3Window*w=[[BDDiag3Window alloc]initWithWindowScene:scene];
            w.frame=UIScreen.mainScreen.bounds;w.windowLevel=UIWindowLevelAlert+100;
            UIViewController*vc=[UIViewController new];vc.view.backgroundColor=UIColor.clearColor;w.rootViewController=vc;
            UIView*panel=[[UIView alloc]initWithFrame:CGRectMake(6,220,168,104)];
            panel.backgroundColor=[[UIColor blackColor]colorWithAlphaComponent:0.78];panel.layer.cornerRadius=10;
            UILabel*lab=[[UILabel alloc]initWithFrame:CGRectMake(8,6,152,20)];lab.textColor=UIColor.whiteColor;lab.font=[UIFont systemFontOfSize:11];lab.text=@"BDDiag3 待采集";g_statusLabel=lab;[panel addSubview:lab];
            UIButton*b1=[UIButton buttonWithType:UIButtonTypeSystem];b1.frame=CGRectMake(8,30,74,34);
            b1.backgroundColor=[[UIColor systemGreenColor]colorWithAlphaComponent:0.9];[b1 setTitle:@"开始采集" forState:UIControlStateNormal];
            [b1 setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];b1.titleLabel.font=[UIFont boldSystemFontOfSize:13];b1.layer.cornerRadius=7;
            [b1 addTarget:BDDiag3Store.class action:@selector(startCapture) forControlEvents:UIControlEventTouchUpInside];
            UIButton*b2=[UIButton buttonWithType:UIButtonTypeSystem];b2.frame=CGRectMake(88,30,72,34);
            b2.backgroundColor=[[UIColor systemBlueColor]colorWithAlphaComponent:0.9];[b2 setTitle:@"结束导出" forState:UIControlStateNormal];
            [b2 setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];b2.titleLabel.font=[UIFont boldSystemFontOfSize:13];b2.layer.cornerRadius=7;
            [b2 addTarget:BDDiag3Store.class action:@selector(exportReport) forControlEvents:UIControlEventTouchUpInside];
            UILabel*tip=[[UILabel alloc]initWithFrame:CGRectMake(8,68,154,30)];tip.textColor=[[UIColor whiteColor]colorWithAlphaComponent:0.8];
            tip.font=[UIFont systemFontOfSize:9];tip.numberOfLines=2;tip.text=@"开始后去走短信登录，120秒自动停";[panel addSubview:tip];
            UIPanGestureRecognizer*pan=[[UIPanGestureRecognizer alloc]initWithTarget:panel action:@selector(bd3_drag:)];[panel addGestureRecognizer:pan];
            [panel addSubview:b1];[panel addSubview:b2];[vc.view addSubview:panel];
            w.hidden=NO;g_win=w;
        }@finally{t_suppress--;}
    });
}
@interface UIView (BD3Drag) -(void)bd3_drag:(UIPanGestureRecognizer*)g;@end
@implementation UIView (BD3Drag)
-(void)bd3_drag:(UIPanGestureRecognizer*)g{CGPoint t=[g translationInView:self.superview];CGPoint c=self.center;c.x+=t.x;c.y+=t.y;self.center=c;[g setTranslation:CGPointZero inView:self.superview];}
@end

// ============================== 入口 ==============================
__attribute__((constructor)) static void bddiag3_entry(void){
    @autoreleasepool{
        NSBundle*mb=NSBundle.mainBundle;NSString*bid=mb.bundleIdentifier?:@"";NSString*bp=mb.bundlePath?:@"";
        if([bp containsString:@".appex/"])return;
        if(![bid isEqualToString:@"com.baidu.BaiduMobileInfo"])return;

        Dl_info di;memset(&di,0,sizeof(di));
        if(dladdr((void*)&bddiag3_entry,&di)&&di.dli_fbase){
            const struct mach_header_64*mh=(const struct mach_header_64*)di.dli_fbase;uintptr_t base=(uintptr_t)di.dli_fbase;
            const struct load_command*lc=(const struct load_command*)((const uint8_t*)mh+sizeof(struct mach_header_64));
            for(uint32_t i=0;i<mh->ncmds;i++,lc=(const void*)((const uint8_t*)lc+lc->cmdsize))
                if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64*seg=(const struct segment_command_64*)lc;
                    if(strncmp(seg->segname,"__TEXT",6)==0){g_ownLow=base;g_ownHigh=base+seg->vmsize;}}
        }
        g_records=[NSMutableArray array];g_bySel=[NSMutableDictionary dictionary];g_sampleGroup=dispatch_group_create();
        _dyld_register_func_for_add_image(b3_imageAdded);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.3*NSEC_PER_SEC)),dispatch_get_main_queue(),^{b3_startDiscoverCycle();});
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{b3_float();});
    }
}
