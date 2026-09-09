#import <UIKit/UIKit.h>
#import "HMEngine.h"

static HMEngine *gEngine;
static dispatch_queue_t gWorker;

static void HMMessage(UIViewController *vc, NSString *title, NSString *message) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
    [vc presentViewController:alert animated:YES completion:nil];
}
static NSString *HMReportText(NSDictionary *report) {
    if (!report) return @"没有结果";
    NSMutableString *text = [NSMutableString stringWithFormat:@"容器：%@\n编号：%@\n\n", report[@"container"][@"name"] ?: @"—", report[@"id"] ?: @"—"];
    for (NSDictionary *entry in report[@"results"]) [text appendFormat:@"%@%@%@\n\n", entry[@"name"] ?: @"", entry[@"name"] ? @"\n" : @"", entry[@"result"] ?: @"未知状态"];
    [text appendString:report[@"note"] ?: @"备份保存在本机。钥匙串未操作。"];
    return text;
}

@interface HMBaseController : UITableViewController
@property(nonatomic) BOOL busy;
- (void)run:(id (^)(NSError **error))work finish:(void (^)(id result, NSError *error))finish;
@end
@implementation HMBaseController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }
- (void)viewDidLoad {
    [super viewDidLoad]; self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 75;
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
}
- (void)run:(id (^)(NSError **error))work finish:(void (^)(id result, NSError *error))finish {
    if (self.busy) return;
    self.busy = YES; gEngine.cancelRequested = NO;
    self.tableView.userInteractionEnabled = NO; self.navigationItem.hidesBackButton = YES;
    for (UIBarButtonItem *button in self.toolbarItems) button.enabled = NO;
    for (UIBarButtonItem *button in self.navigationItem.rightBarButtonItems) button.enabled = NO;
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    [spinner startAnimating]; self.navigationItem.titleView = spinner;
    __block UIBackgroundTaskIdentifier task = UIBackgroundTaskInvalid;
    task = [UIApplication.sharedApplication beginBackgroundTaskWithName:@"HMCleaner operation" expirationHandler:^{
        gEngine.cancelRequested = YES;
        if (task != UIBackgroundTaskInvalid) { [UIApplication.sharedApplication endBackgroundTask:task]; task = UIBackgroundTaskInvalid; }
    }];
    dispatch_async(gWorker, ^{
        @autoreleasepool {
            NSError *error = nil; id result = nil;
            @try { result = work(&error); }
            @catch (NSException *exception) { error = HMError([@"操作异常，已停止：" stringByAppendingString:exception.reason ?: @"未知"]); }
            dispatch_async(dispatch_get_main_queue(), ^{
                if (task != UIBackgroundTaskInvalid) { [UIApplication.sharedApplication endBackgroundTask:task]; task = UIBackgroundTaskInvalid; }
                self.busy = NO; self.tableView.userInteractionEnabled = YES; self.navigationItem.hidesBackButton = NO;
                self.navigationItem.titleView = nil;
                for (UIBarButtonItem *button in self.toolbarItems) button.enabled = YES;
                for (UIBarButtonItem *button in self.navigationItem.rightBarButtonItems) button.enabled = YES;
                finish(result, error);
            });
        }
    });
}
@end

@interface HMRecordController : HMBaseController
@property(nonatomic, strong) NSDictionary *record;
@property(nonatomic, copy) NSString *report;
@end
@implementation HMRecordController
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"备份与验证";
    self.report = HMReportText(self.record);
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"导出记录" style:UIBarButtonItemStylePlain target:self action:@selector(exportReport)];
    self.toolbarItems = @[[[UIBarButtonItem alloc] initWithTitle:@"重新验证" style:UIBarButtonItemStylePlain target:self action:@selector(verify)],
                         [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil],
                         [[UIBarButtonItem alloc] initWithTitle:@"恢复缺失文件" style:UIBarButtonItemStylePlain target:self action:@selector(restore)]];
}
- (void)viewWillAppear:(BOOL)animated { [super viewWillAppear:animated]; [self.navigationController setToolbarHidden:NO animated:animated]; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return 2; }
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone; cell.textLabel.numberOfLines = 0;
    cell.textLabel.font = [UIFont systemFontOfSize:14];
    cell.textLabel.text = path.row == 0 ? self.report : [NSString stringWithFormat:@"目标：%@\n容器 ID：%@\n主目录：%@\n\n恢复仅处理仍不存在的文件；不会覆盖重新生成的内容。恢复内容及基本权限，不恢复时间戳、ACL 和扩展属性。",
                                                       HMTargetID, self.record[@"container"][@"id"], self.record[@"container"][@"root"]];
    return cell;
}
- (void)verify {
    [self run:^id(NSError **error) { return [gEngine verify:self.record error:error]; } finish:^(id result, NSError *error) {
        if (result) { self.report = HMReportText(result); [self.tableView reloadData]; }
        if (error) HMMessage(self, @"验证未完成", error.localizedDescription);
    }];
}
- (void)restore {
    NSString *message = [NSString stringWithFormat:@"容器：%@\n\n仅恢复这份备份中当前不存在的文件。已有内容不覆盖。请先划掉河马剧场。", self.record[@"container"][@"name"]];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"恢复文件内容" message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"恢复缺失文件" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self run:^id(NSError **error) { return [gEngine restore:self.record error:error]; } finish:^(id result, NSError *error) {
            if (result) { self.report = HMReportText(result); [self.tableView reloadData]; }
            if (error) HMMessage(self, @"恢复未全部完成", error.localizedDescription);
        }];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)exportReport {
    // Sharing is user initiated; file contents and Keychain values are never included.
    UIActivityViewController *share = [[UIActivityViewController alloc] initWithActivityItems:@[self.report] applicationActivities:nil];
    share.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItem;
    [self presentViewController:share animated:YES completion:nil];
}
@end

@interface HMScanController : HMBaseController
@property(nonatomic, strong) NSDictionary *container;
@property(nonatomic, strong) NSArray<HMScanItem *> *items;
@property(nonatomic, copy) NSString *scanStatus;
@end
@implementation HMScanController
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = self.container[@"name"];
    self.scanStatus = @"尚未扫描";
    self.toolbarItems = @[[[UIBarButtonItem alloc] initWithTitle:@"重新扫描" style:UIBarButtonItemStylePlain target:self action:@selector(scan)],
                         [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil],
                         [[UIBarButtonItem alloc] initWithTitle:@"备份并清理勾选项" style:UIBarButtonItemStylePlain target:self action:@selector(clean)]];
    [self scan];
}
- (void)viewWillAppear:(BOOL)animated { [super viewWillAppear:animated]; [self.navigationController setToolbarHidden:NO animated:animated]; }
- (void)scan {
    self.items = nil; [self.tableView reloadData];
    [self run:^id(NSError **error) { return [gEngine scan:self.container error:error]; } finish:^(id result, NSError *error) {
        self.items = result;
        self.scanStatus = error ? error.localizedDescription : @"扫描完成；勾选后才会清理。SDK 归属尚未证实，按文件证据分组。";
        [self.tableView reloadData];
    }];
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 6; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0 || section == 4) return 1;
    if (section == 5) return [self.container[@"paths"] count];
    if (!self.items.count) return 0;
    return section == 3 ? 1 : 2;
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return @[@"所选容器", @"PID4SM / FP_SEQ", @"come2 / PdnuLKiM", @"缓存文件", @"钥匙串（待核实）", @"Crane 返回的目录（只读）"][section];
}
- (HMScanItem *)itemAt:(NSIndexPath *)path { return self.items[(path.section - 1) * 2 + path.row]; }
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0; cell.detailTextLabel.numberOfLines = 0;
    cell.textLabel.font = [UIFont systemFontOfSize:15]; cell.detailTextLabel.font = [UIFont systemFontOfSize:12];
    if (path.section == 0) {
        cell.textLabel.text = self.scanStatus;
        cell.detailTextLabel.text = [NSString stringWithFormat:@"河马剧场 · %@\n容器 ID：%@\n主目录：%@", HMTargetID, self.container[@"id"], self.container[@"root"]];
    } else if (path.section == 4) {
        cell.textLabel.text = @"未启用 · 不会清理钥匙串";
        cell.detailTextLabel.text = @"日志里 FP_SEQ 的 service/account 可见，但实际访问组与容器映射尚未核实。其他项存在脱敏字段，不能据此制定删除规则。";
    } else if (path.section == 5) {
        NSDictionary *p = self.container[@"paths"][path.row];
        NSArray *types = @[@"主应用", @"共享目录", @"扩展"];
        NSInteger type = [p[@"type"] integerValue];
        cell.textLabel.text = type >= 0 && type < 3 ? types[type] : @"其他";
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@\n%@", p[@"id"], p[@"canonical"]];
    } else {
        HMScanItem *item = [self itemAt:path];
        cell.textLabel.text = item.name; cell.detailTextLabel.text = item.summary;
        cell.accessoryType = item.selected ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
        cell.textLabel.textColor = item.readError ? UIColor.secondaryLabelColor : UIColor.labelColor;
    }
    return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    [tableView deselectRowAtIndexPath:path animated:YES];
    if (path.section >= 1 && path.section <= 3) {
        HMScanItem *item = [self itemAt:path];
        if (!item.readError) { item.selected = !item.selected; [tableView reloadRowsAtIndexPaths:@[path] withRowAnimation:UITableViewRowAnimationNone]; }
    }
}
- (void)clean {
    NSMutableArray *names = [NSMutableArray array];
    for (HMScanItem *item in self.items) if (item.selected) [names addObject:item.name];
    if (!names.count) { HMMessage(self, @"未勾选文件", @"请先勾选实际存在的文件。"); return; }
    NSString *message = [NSString stringWithFormat:@"河马剧场 / %@\n容器 ID：%@\n\n%@\n\n先保存备份，再清理以上 %lu 项。请先划掉河马剧场，执行期间不要打开或切换容器。钥匙串不在本次范围。",
                         self.container[@"name"], self.container[@"id"], [names componentsJoinedByString:@"\n"], (unsigned long)names.count];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"核对清理范围" message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"备份并清理" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [self run:^id(NSError **error) { return [gEngine clean:self.container items:self.items error:error]; } finish:^(id result, NSError *error) {
            // Invalidate old fingerprints even if only some files were changed.
            self.items = nil; self.scanStatus = @"操作结束，请重新扫描"; [self.tableView reloadData];
            if (result) { HMRecordController *record = [HMRecordController new]; record.record = result; [self.navigationController pushViewController:record animated:YES]; }
            if (error) HMMessage(self, @"清理未完成", error.localizedDescription);
        }];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end

@interface HMHistoryController : HMBaseController
@property(nonatomic, strong) NSArray<NSDictionary *> *records;
@property(nonatomic, copy) NSString *status;
@end
@implementation HMHistoryController
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"本机备份";
    [self run:^id(NSError **error) { return [gEngine history:error]; } finish:^(id result, NSError *error) {
        self.records = result; self.status = error ? [@"暂无可读取的备份：" stringByAppendingString:error.localizedDescription] : @"备份不会自动删除";
        [self.tableView reloadData];
    }];
}
- (void)viewWillAppear:(BOOL)animated { [super viewWillAppear:animated]; [self.navigationController setToolbarHidden:YES animated:animated]; }
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section { return self.status; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return self.records.count; }
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    NSDictionary *record = self.records[path.row];
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = record[@"container"][@"name"] ?: @"不完整记录";
    cell.detailTextLabel.numberOfLines = 0;
    cell.detailTextLabel.text = record[@"invalid"] ?: [NSString stringWithFormat:@"%@\n%lu 项 · %@", record[@"created"], (unsigned long)[record[@"entries"] count], record[@"prepared"]];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator; return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    [tableView deselectRowAtIndexPath:path animated:YES]; NSDictionary *record = self.records[path.row];
    if (record[@"invalid"]) { HMMessage(self, @"记录不完整", record[@"invalid"]); return; }
    HMRecordController *vc = [HMRecordController new]; vc.record = record; [self.navigationController pushViewController:vc animated:YES];
}
@end

@interface HMHomeController : HMBaseController
@property(nonatomic, strong) NSArray<NSDictionary *> *containers;
@property(nonatomic, copy) NSString *status;
@end
@implementation HMHomeController
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"河马清理 0.1.0";
    self.navigationItem.rightBarButtonItems = @[[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refresh)],
                                              [[UIBarButtonItem alloc] initWithTitle:@"备份" style:UIBarButtonItemStylePlain target:self action:@selector(history)]];
    [self refresh];
}
- (void)viewWillAppear:(BOOL)animated { [super viewWillAppear:animated]; [self.navigationController setToolbarHidden:YES animated:animated]; }
- (void)refresh {
    [self run:^id(NSError **error) { return [gEngine.environment containers:error]; } finish:^(id result, NSError *error) {
        self.containers = result;
        self.status = error ? error.localizedDescription : @"选择要检查的容器。打开本 App 不会自动清理或写入目标容器。";
        [self.tableView reloadData];
    }];
}
- (void)history { [self.navigationController pushViewController:[HMHistoryController new] animated:YES]; }
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 2; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return section == 0 ? 1 : self.containers.count; }
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section { return section == 0 ? @"河马剧场 · com.cbn.hmjc" : @"Crane 容器"; }
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return section == 1 ? @"只处理日志列出的 5 个具体文件。共享目录、扩展目录只展示。钥匙串映射待核实，未启用清理。" : nil;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0; cell.detailTextLabel.numberOfLines = 0;
    if (!path.section) { cell.textLabel.text = self.status; cell.detailTextLabel.text = gEngine.environment.detail; }
    else {
        NSDictionary *row = self.containers[path.row];
        cell.textLabel.text = row[@"name"];
        cell.detailTextLabel.text = [row[@"problem"] length] ? row[@"problem"] : [NSString stringWithFormat:@"%@\n%@", row[@"id"], [row[@"active"] boolValue] ? @"Crane 最近启用的容器" : @"点按扫描预览"];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
    [tableView deselectRowAtIndexPath:path animated:YES]; if (!path.section) return;
    NSDictionary *row = self.containers[path.row];
    if ([row[@"problem"] length]) { HMMessage(self, @"容器无法确认", row[@"problem"]); return; }
    HMScanController *vc = [HMScanController new]; vc.container = row;
    [self.navigationController pushViewController:vc animated:YES];
}
@end

@interface HMAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation HMAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    gWorker = dispatch_queue_create("com.codex.hmcleaner.worker", DISPATCH_QUEUE_SERIAL);
    gEngine = [[HMEngine alloc] initWithEnvironment:[HMEnvironment new] storePath:@"/private/var/mobile/Library/Application Support/HMCleaner/Backups"];
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:[HMHomeController new]];
    [self.window makeKeyAndVisible]; return YES;
}
@end
int main(int argc, char **argv) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(HMAppDelegate.class)); }
}
