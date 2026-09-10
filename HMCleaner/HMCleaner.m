#import <UIKit/UIKit.h>
#import <errno.h>
#import <spawn.h>
#import <string.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

static NSString *const HMHelperPath = @"/usr/local/bin/hmcleaner";

static void HMShowMessage(UIViewController *controller, NSString *title, NSString *message) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"知道了"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [controller presentViewController:alert animated:YES completion:nil];
}

@interface HMHomeController : UIViewController
@property(nonatomic, strong) UILabel *stateLabel;
@property(nonatomic, strong) UILabel *detailLabel;
@property(nonatomic, strong) UIButton *cleanButton;
@property(nonatomic, strong) UIButton *scanButton;
@property(nonatomic, strong) UITextView *outputView;
@property(nonatomic, strong) UIActivityIndicatorView *spinner;
@property(nonatomic) BOOL running;
@end

@implementation HMHomeController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"河马清理";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    UILabel *titleLabel = [UILabel new];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    titleLabel.text = @"河马清理 1.2.0";
    titleLabel.font = [UIFont systemFontOfSize:28 weight:UIFontWeightBold];
    titleLabel.textAlignment = NSTextAlignmentCenter;

    self.stateLabel = [UILabel new];
    self.stateLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.stateLabel.text = @"准备就绪";
    self.stateLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightSemibold];
    self.stateLabel.textAlignment = NSTextAlignmentCenter;

    self.detailLabel = [UILabel new];
    self.detailLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.detailLabel.text = @"目标固定为河马剧场 com.cbn.hmjc\n自动处理主容器和全部 Crane 分身";
    self.detailLabel.font = [UIFont systemFontOfSize:14];
    self.detailLabel.textColor = UIColor.secondaryLabelColor;
    self.detailLabel.textAlignment = NSTextAlignmentCenter;
    self.detailLabel.numberOfLines = 0;

    self.cleanButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.cleanButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.cleanButton setTitle:@"执行全部清理" forState:UIControlStateNormal];
    [self.cleanButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.cleanButton.titleLabel.font = [UIFont systemFontOfSize:20 weight:UIFontWeightBold];
    self.cleanButton.backgroundColor = UIColor.systemRedColor;
    self.cleanButton.layer.cornerRadius = 14;
    [self.cleanButton addTarget:self action:@selector(confirmClean) forControlEvents:UIControlEventTouchUpInside];

    self.scanButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.scanButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.scanButton setTitle:@"只读检测容器" forState:UIControlStateNormal];
    self.scanButton.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    [self.scanButton addTarget:self action:@selector(scanOnly) forControlEvents:UIControlEventTouchUpInside];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    self.spinner.hidesWhenStopped = YES;

    self.outputView = [UITextView new];
    self.outputView.translatesAutoresizingMaskIntoConstraints = NO;
    self.outputView.editable = NO;
    self.outputView.selectable = YES;
    self.outputView.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
    self.outputView.textColor = UIColor.labelColor;
    self.outputView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.outputView.layer.cornerRadius = 12;
    self.outputView.textContainerInset = UIEdgeInsetsMake(12, 10, 12, 10);
    self.outputView.text = @"点“只读检测容器”可先核对范围；点红色按钮执行完整清理。";

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        titleLabel, self.stateLabel, self.detailLabel, self.cleanButton,
        self.scanButton, self.spinner, self.outputView
    ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    [self.view addSubview:stack];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:18],
        [stack.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-18],
        [stack.topAnchor constraintEqualToAnchor:safe.topAnchor constant:20],
        [stack.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-16],
        [self.cleanButton.heightAnchor constraintEqualToConstant:58],
        [self.scanButton.heightAnchor constraintEqualToConstant:42],
        [self.outputView.heightAnchor constraintGreaterThanOrEqualToConstant:240]
    ]];
    [titleLabel setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisVertical];
    [self.stateLabel setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisVertical];
    [self.detailLabel setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisVertical];
    [self.cleanButton setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisVertical];
    [self.scanButton setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisVertical];
    [self.spinner setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisVertical];
}

- (void)setBusy:(BOOL)busy label:(NSString *)label {
    self.running = busy;
    self.cleanButton.enabled = !busy;
    self.scanButton.enabled = !busy;
    self.cleanButton.alpha = busy ? 0.55 : 1.0;
    self.scanButton.alpha = busy ? 0.55 : 1.0;
    self.stateLabel.text = label;
    if (busy) [self.spinner startAnimating]; else [self.spinner stopAnimating];
}

- (void)scanOnly {
    [self runMode:@"list" destructive:NO];
}

- (void)confirmClean {
    if (self.running) return;
    NSString *message = @"将结束河马剧场，清空主容器和全部 Crane 分身，并删除河马钥匙串访问组。\n\n普通文件不会逐个备份，删除后不可恢复；钥匙串会先生成容器外备份。";
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"确认执行全部清理？"
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [alert addAction:[UIAlertAction actionWithTitle:@"执行清理"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        [weakSelf runMode:@"all" destructive:YES];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)appendOutput:(NSString *)text {
    self.outputView.text = text.length ? text : @"（没有输出）";
    NSRange end = NSMakeRange(self.outputView.text.length, 0);
    [self.outputView scrollRangeToVisible:end];
}

- (void)runMode:(NSString *)mode destructive:(BOOL)destructive {
    if (self.running) return;
    if (![@[@"list", @"all"] containsObject:mode]) {
        HMShowMessage(self, @"拒绝执行", @"App 只允许固定的检测和全部清理模式。");
        return;
    }
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:HMHelperPath]) {
        HMShowMessage(self, @"清理助手缺失", @"请通过 Sileo 重新安装完整的 HMCleaner 1.2.0 软件包。");
        return;
    }

    [self setBusy:YES label:destructive ? @"正在清理，请勿打开河马…" : @"正在检测容器…"];
    self.outputView.text = @"";
    NSString *path = HMHelperPath;
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int pipes[2] = {-1, -1};
        if (pipe(pipes) != 0) {
            int saved = errno;
            dispatch_async(dispatch_get_main_queue(), ^{
                [weakSelf finishMode:mode status:127 output:@"" launchError:saved];
            });
            return;
        }

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, pipes[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, pipes[0]);
        posix_spawn_file_actions_addclose(&actions, pipes[1]);

        pid_t pid = 0;
        const char *executable = path.fileSystemRepresentation;
        const char *argument = mode.UTF8String;
        char *const argv[] = {(char *)executable, (char *)argument, NULL};
        int spawnResult = posix_spawn(&pid, executable, &actions, NULL, argv, environ);
        posix_spawn_file_actions_destroy(&actions);
        close(pipes[1]);

        if (spawnResult != 0) {
            close(pipes[0]);
            dispatch_async(dispatch_get_main_queue(), ^{
                [weakSelf finishMode:mode status:127 output:@"" launchError:spawnResult];
            });
            return;
        }

        NSMutableData *data = [NSMutableData data];
        uint8_t buffer[4096];
        ssize_t count = 0;
        while ((count = read(pipes[0], buffer, sizeof(buffer))) > 0) {
            [data appendBytes:buffer length:(NSUInteger)count];
            NSString *partial = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (partial) {
                dispatch_async(dispatch_get_main_queue(), ^{ [weakSelf appendOutput:partial]; });
            }
        }
        close(pipes[0]);

        int waitStatus = 0;
        pid_t waited = 0;
        do { waited = waitpid(pid, &waitStatus, 0); } while (waited < 0 && errno == EINTR);
        int exitCode = waited < 0 ? 127 : (WIFEXITED(waitStatus) ? WEXITSTATUS(waitStatus) : 128 + WTERMSIG(waitStatus));
        NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"输出不是有效的 UTF-8";
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf finishMode:mode status:exitCode output:output launchError:0];
        });
    });
}

- (void)finishMode:(NSString *)mode status:(int)status output:(NSString *)output launchError:(int)launchError {
    if (launchError) {
        NSString *reason = [NSString stringWithUTF8String:strerror(launchError)] ?: @"未知错误";
        [self appendOutput:[NSString stringWithFormat:@"无法启动清理助手：%@ (%d)", reason, launchError]];
        [self setBusy:NO label:@"启动失败"];
        HMShowMessage(self, @"无法执行", self.outputView.text);
        return;
    }

    [self appendOutput:output];
    if (status == 0) {
        BOOL cleaned = [mode isEqualToString:@"all"];
        [self setBusy:NO label:cleaned ? @"清理完成" : @"检测完成"];
        if (cleaned) HMShowMessage(self, @"清理完成", @"现在换 IP，把河马从后台划掉后重新打开，再进行注册。");
    } else {
        [self setBusy:NO label:[NSString stringWithFormat:@"执行失败（退出码 %d）", status]];
        HMShowMessage(self, @"清理未完成", @"程序已按安全规则中止。请保留页面输出，不要连续重复点击。普通文件阶段已完成的删除不会自动回滚。");
    }
}

@end

@interface HMAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation HMAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    HMHomeController *home = [HMHomeController new];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:home];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(HMAppDelegate.class));
    }
}
