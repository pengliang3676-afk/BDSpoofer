#import <UIKit/UIKit.h>
#import <math.h>
#import "BDSConfigPolicy.h"

static UIColor *BDSRandomButtonColor(NSUInteger index) {
    return @[[UIColor colorWithRed:0.82 green:0.17 blue:0.23 alpha:1],
             [UIColor colorWithRed:0.10 green:0.50 blue:0.28 alpha:1],
             [UIColor colorWithRed:0.08 green:0.38 blue:0.84 alpha:1]][MIN(index,2)];
}

@interface BDSActionPage : UITableViewController
@property(nonatomic,copy) NSArray<NSDictionary *> *items;
@property(nonatomic,copy) NSString *pageSummary;
@property(nonatomic,copy) NSString *(^summaryProvider)(void);
@end
@implementation BDSActionPage
- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.rowHeight=56;
    self.tableView.sectionHeaderHeight=UITableViewAutomaticDimension;
    self.tableView.estimatedSectionHeaderHeight=250;
    self.tableView.separatorStyle=UITableViewCellSeparatorStyleNone;
    self.navigationItem.rightBarButtonItem=[[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStylePlain target:self action:@selector(close)];
}
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if(self.summaryProvider) self.pageSummary=self.summaryProvider();
    [self.tableView reloadData];
}
- (void)close { [self dismissViewControllerAnimated:YES completion:nil]; }
- (BOOL)usesCompactActionRow { return self.items.count==7; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return [self usesCompactActionRow] ? 5 : self.items.count; }
- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section {
    CGFloat textWidth=MAX(120, CGRectGetWidth(tableView.bounds)-68);
    CGRect bounds=[self.pageSummary ?: @"" boundingRectWithSize:CGSizeMake(textWidth,CGFLOAT_MAX)
                                                    options:NSStringDrawingUsesLineFragmentOrigin|NSStringDrawingUsesFontLeading
                                                 attributes:@{NSFontAttributeName:[UIFont systemFontOfSize:14]}
                                                    context:nil];
    return MAX(44, ceil(bounds.size.height)+44);
}
- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section {
    CGFloat height=[self tableView:tableView heightForHeaderInSection:section];
    UIView *header=[[UIView alloc] initWithFrame:CGRectMake(0,0,CGRectGetWidth(tableView.bounds),height)];
    UIView *card=[[UIView alloc] initWithFrame:CGRectMake(8,6,CGRectGetWidth(header.bounds)-16,height-12)];
    card.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    card.backgroundColor=UIColor.secondarySystemGroupedBackgroundColor;
    card.layer.cornerRadius=13;
    card.layer.masksToBounds=YES;
    UILabel *label=[[UILabel alloc] initWithFrame:CGRectInset(card.bounds,16,12)];
    label.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    label.numberOfLines=0;
    label.font=[UIFont systemFontOfSize:14];
    label.textColor=UIColor.labelColor;
    label.text=self.pageSummary;
    [card addSubview:label];
    [header addSubview:card];
    return header;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.backgroundColor=UIColor.clearColor;
    cell.selectionStyle=UITableViewCellSelectionStyleNone;
    if([self usesCompactActionRow] && indexPath.row==3) {
        UIStackView *row=[[UIStackView alloc] init];
        row.translatesAutoresizingMaskIntoConstraints=NO;
        row.axis=UILayoutConstraintAxisHorizontal;
        row.distribution=UIStackViewDistributionFillEqually;
        row.spacing=6;
        for(NSUInteger i=3;i<=5;i++) {
            UIButton *button=[UIButton buttonWithType:UIButtonTypeSystem];
            button.tag=i;
            button.backgroundColor=UIColor.secondarySystemGroupedBackgroundColor;
            button.layer.cornerRadius=11;
            button.layer.masksToBounds=YES;
            button.titleLabel.font=[UIFont boldSystemFontOfSize:15];
            button.titleLabel.adjustsFontSizeToFitWidth=YES;
            button.titleLabel.minimumScaleFactor=0.72;
            [button setTitle:self.items[i][@"title"] forState:UIControlStateNormal];
            [button setTitleColor:(i==5 ? UIColor.systemRedColor : UIColor.labelColor) forState:UIControlStateNormal];
            [button addTarget:self action:@selector(runCompactAction:) forControlEvents:UIControlEventTouchUpInside];
            [row addArrangedSubview:button];
        }
        [cell.contentView addSubview:row];
        [NSLayoutConstraint activateConstraints:@[
            [row.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:8],
            [row.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-8],
            [row.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:5],
            [row.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-5]]];
        return cell;
    }
    NSUInteger itemIndex=([self usesCompactActionRow] && indexPath.row==4) ? 6 : indexPath.row;
    NSDictionary *item=self.items[itemIndex];
    UILabel *label=[[UILabel alloc] init];
    label.translatesAutoresizingMaskIntoConstraints=NO;
    label.text=item[@"title"];
    label.font=[UIFont boldSystemFontOfSize:16];
    label.textAlignment=NSTextAlignmentCenter;
    label.adjustsFontSizeToFitWidth=YES;
    label.minimumScaleFactor=0.7;
    label.backgroundColor=item[@"color"] ?: UIColor.secondarySystemGroupedBackgroundColor;
    label.textColor=item[@"color"] ? UIColor.whiteColor : UIColor.labelColor;
    label.layer.cornerRadius=11;
    label.layer.masksToBounds=YES;
    [cell.contentView addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:8],
        [label.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-8],
        [label.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:5],
        [label.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-5]]];
    return cell;
}
- (void)runCompactAction:(UIButton *)sender {
    if(sender.tag>=self.items.count) return;
    void (^action)(void)=self.items[sender.tag][@"action"];
    if(action) action();
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    if([self usesCompactActionRow] && indexPath.row==3) return;
    NSUInteger itemIndex=([self usesCompactActionRow] && indexPath.row==4) ? 6 : indexPath.row;
    void (^action)(void)=self.items[itemIndex][@"action"];
    if(action) action();
}
@end

@interface BDSAssociationPage : UITableViewController
@property(nonatomic,copy) NSDictionary *configuration;
@property(nonatomic,copy) BOOL (^saveChanges)(NSDictionary *);
@property(nonatomic,copy) void (^editParameters)(NSUInteger);
@property(nonatomic,strong) NSMutableIndexSet *expanded;
@end
@implementation BDSAssociationPage
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title=@"反关联设置";
    self.expanded=[NSMutableIndexSet indexSetWithIndex:0];
    self.tableView.rowHeight=UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight=56;
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 3; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [self.expanded containsIndex:section] ? BDSSettingGroups()[section].count+(self.editParameters?1:0) : 0;
}
- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section { return 52; }
- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section {
    UIButton *button=[UIButton buttonWithType:UIButtonTypeSystem];
    button.tag=section;
    button.contentHorizontalAlignment=UIControlContentHorizontalAlignmentLeading;
    UIButtonConfiguration *style=[UIButtonConfiguration plainButtonConfiguration];
    style.contentInsets=NSDirectionalEdgeInsetsMake(0,16,0,16);
    button.configuration=style;
    button.titleLabel.font=[UIFont boldSystemFontOfSize:17];
    NSString *name=@[@"基础参数",@"高级参数",@"反关联参数"][section];
    [button setTitle:[NSString stringWithFormat:@"%@  %@",[self.expanded containsIndex:section]?@"▾":@"▸",name] forState:UIControlStateNormal];
    [button addTarget:self action:@selector(toggleGroup:) forControlEvents:UIControlEventTouchUpInside];
    return button;
}
- (void)toggleGroup:(UIButton *)sender {
    if([self.expanded containsIndex:sender.tag]) [self.expanded removeIndex:sender.tag];
    else [self.expanded addIndex:sender.tag];
    [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:sender.tag] withRowAnimation:UITableViewRowAnimationAutomatic];
}
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if(section==0) return @"常规开关在首次初始化时开启，后续保留手动选择。";
    if(section==1 && [self.expanded containsIndex:1]) return @"标注默认关闭的 4 项保持关闭，需要时单独调整。";
    if(section==2) return @"修改后彻底关闭百度再打开。";
    return nil;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    NSArray *group=BDSSettingGroups()[indexPath.section];
    if(indexPath.row>=group.count) {
        cell.textLabel.text=@"编辑参数"; cell.accessoryType=UITableViewCellAccessoryDisclosureIndicator; return cell;
    }
    NSDictionary *item=group[indexPath.row];
    cell.textLabel.text=item[@"name"];
    cell.textLabel.numberOfLines=0;
    cell.detailTextLabel.text=[item[@"off"] boolValue]?@"默认关闭":nil;
    UISwitch *toggle=[[UISwitch alloc] init];
    toggle.on=[self.configuration[item[@"key"]] boolValue];
    toggle.tag=indexPath.section*100+indexPath.row;
    toggle.accessibilityLabel=item[@"name"];
    [toggle addTarget:self action:@selector(changeSwitch:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView=toggle;
    cell.selectionStyle=UITableViewCellSelectionStyleNone;
    return cell;
}
- (void)changeSwitch:(UISwitch *)sender {
    NSString *key=BDSSettingGroups()[sender.tag/100][sender.tag%100][@"key"];
    NSDictionary *changes=@{key:@(sender.on)};
    if(self.saveChanges && self.saveChanges(changes)) {
        NSMutableDictionary *updated=[self.configuration mutableCopy]; [updated addEntriesFromDictionary:changes]; self.configuration=updated;
    } else {
        sender.on=!sender.on;
        UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"保存失败" message:@"设置没有完整写入，请返回后刷新再试。" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.row==BDSSettingGroups()[indexPath.section].count && self.editParameters) self.editParameters(indexPath.section);
}
@end

@interface BDSTargetedPage : UITableViewController
@property(nonatomic,strong) NSMutableSet<NSString *> *selection;
@property(nonatomic,copy) BOOL (^selectionChanged)(NSSet<NSString *> *);
@property(nonatomic,copy) void (^randomize)(void);
@end
@implementation BDSTargetedPage
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title=@"定向指纹参数";
    self.tableView.rowHeight=56;
    if(!self.selection) self.selection=[NSMutableSet set];
    UIButton *button=[UIButton buttonWithType:UIButtonTypeSystem];
    button.frame=CGRectMake(0,0,320,52);
    button.backgroundColor=BDSRandomButtonColor(2);
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [button setTitle:@"一键随机定向指纹参数" forState:UIControlStateNormal];
    button.titleLabel.font=[UIFont boldSystemFontOfSize:16];
    [button addTarget:self action:@selector(runRandom) forControlEvents:UIControlEventTouchUpInside];
    self.tableView.tableFooterView=button;
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section { return @"选择需要随机的项目；只更换已选项目的参数。"; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return 5; }
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.text=@[@"系统版本参数",@"机型标识参数",@"屏幕参数",@"User-Agent 参数",@"Push 参数"][indexPath.row];
    UISwitch *toggle=[[UISwitch alloc] init]; toggle.tag=indexPath.row;
    toggle.on=[self.selection containsObject:BDSSelectedTargetKeys()[indexPath.row]];
    [toggle addTarget:self action:@selector(changeSelection:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView=toggle; cell.selectionStyle=UITableViewCellSelectionStyleNone;
    return cell;
}
- (void)changeSelection:(UISwitch *)sender {
    NSString *key=BDSSelectedTargetKeys()[sender.tag];
    NSMutableSet *next=[self.selection mutableCopy];
    if(sender.on) [next addObject:key]; else [next removeObject:key];
    if(!self.selectionChanged || self.selectionChanged(next)) self.selection=next;
    else sender.on=!sender.on;
}
- (void)runRandom {
    if(!self.selection.count) {
        UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"尚未选择项目" message:@"请先开启至少一项。" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil]; return;
    }
    if(self.randomize) self.randomize();
}
@end
