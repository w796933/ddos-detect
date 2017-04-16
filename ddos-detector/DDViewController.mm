//
//  DDViewController.mm
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import "DDViewController.h"
#import "PCAPAnalyzer.h"

#include <iostream>

using namespace std;

typedef NSDictionary NSAttack;

static const NSString *destCellId = @"DestCellID";
static const NSString *sourceCellId = @"SourceCellID";
static const NSString *protocolCellId = @"ProtocolCellID";
static const NSString *timeCellId = @"PacketNumberCellID";

@interface DDViewController ()

@property (weak) IBOutlet NSTextField *alertLabel;
@property (weak) IBOutlet NSTableView *tableView;

@property (nonatomic, retain) PCAPAnalyzer *analyzer;
@property (nonatomic, retain) NSMutableArray<NSAttack *> *attacks;

@end

@implementation DDViewController

- (instancetype)init
{
    self = [super init];
    if (self) {
        
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.attacks = [NSMutableArray new];
    PCAPAnalyzer *analyzer = [[PCAPAnalyzer alloc] init];
    self.analyzer = analyzer;
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(receiveAttackNotification:)
                                                 name:attackDetectedEvent
                                               object:nil];
}

- (void) viewDidAppear  {
    [super viewDidAppear];
    [self.analyzer analyze];
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

- (void) receiveAttackNotification: (NSNotification *) notification {
    static int counter = 0;
    counter++;
    NSDictionary *dict = [notification userInfo];
    NSAttack *attack = [dict objectForKey:@"attack"];
    [self.attacks addObject:attack];
    [self.alertLabel setStringValue: [NSString stringWithFormat:@"DDoS Attacks: %d", counter]];
    [self.tableView reloadData];
}

#pragma mark - NSTableView

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex {
    NSAttack *attack = [self.attacks objectAtIndex:rowIndex];
    if ([aTableColumn.identifier isEqualToString: destCellId.mutableCopy]) {
        return (NSString *) [attack objectForKey:@"destIp"];
    }
    if ([aTableColumn.identifier isEqualToString: protocolCellId.mutableCopy]) {
        return (NSString *) [attack objectForKey:@"protocol"];
    }
    if ([aTableColumn.identifier isEqualToString:sourceCellId.mutableCopy]) {
        NSMutableString *ips = @"".mutableCopy;
        for (NSString *ip in (NSMutableSet *)[attack objectForKey:@"sourceIps"]) {
            [ips appendString:ip];
            [ips appendString:@","];
        }
        [ips deleteCharactersInRange:NSMakeRange([ips length] - 1, 1)];
        return ips;
    }
    if ([aTableColumn.identifier isEqualToString: timeCellId.mutableCopy]) {
        return [NSString stringWithFormat:@"%@", [attack objectForKey:@"numPackets"]];
    }
    return nil;
}

// TableView Datasource method implementation
- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return self.attacks.count;
}




@end
