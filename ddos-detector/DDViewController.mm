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

@property (nonatomic, retain) PCAPAnalyzer *analyzer;
@property (atomic, retain) NSMutableArray<NSAttack *> *attacks;
@property (nonatomic, assign) CFTimeInterval ticks;
@property (nonatomic, retain) NSTimer *timer;

@end

@implementation DDViewController

- (instancetype)init
{
    self = [super init];
    if (self) {
        
    }
    return self;
}

#pragma mark - View LifeCycle

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.attacks = [NSMutableArray new];
    [self.progressIndicator setMinValue: 0.0];
    [self.progressIndicator setMaxValue: 1.0];
    
    PCAPAnalyzer *analyzer = [[PCAPAnalyzer alloc] init];
    analyzer.delegate = self;
    self.analyzer = analyzer;

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(receivePacketNotification:)
                                                 name:packetEvent
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(endPacketNotification:)
                                                 name:packetFinish
                                               object:nil];
}

- (void) viewDidAppear  {
    [super viewDidAppear];
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

#pragma mark - Notifications

- (void) receivePacketNotification: (NSNotification *) notification {
    NSDictionary *dict = [notification userInfo];
    NSNumber *n = [dict objectForKey: @"counter"];
    [self.alertLabel setStringValue: [NSString stringWithFormat: @"%@", n]];
}

- (void) endPacketNotification: (NSNotification *) notification {
    NSDictionary *dict = [notification userInfo];
    self.attacks = [dict objectForKey: @"attacks"];
    [self.alertLabel setStringValue: @"capture finished"];
    [self.progressIndicator setDoubleValue: 1.0];
    [self.tableView reloadData];
    [self.timer invalidate];
}

#pragma mark - NSTableView

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex {
    NSAttack *attack = [self.attacks objectAtIndex:rowIndex];
    if ([aTableColumn.identifier isEqualToString: destCellId.mutableCopy]) {
        return (NSString *) [attack objectForKey: @"destIp"];
    }
    if ([aTableColumn.identifier isEqualToString: protocolCellId.mutableCopy]) {
        return (NSString *) [attack objectForKey: @"protocol"];
    }
    if ([aTableColumn.identifier isEqualToString:sourceCellId.mutableCopy]) {
        NSMutableString *ips = @"".mutableCopy;
        for (NSString *ip in (NSMutableSet *)[attack objectForKey: @"sourceIps"]) {
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

#pragma mark - View Actions

- (IBAction)analyzeButtonTapped:(id)sender {
    self.timer = [NSTimer scheduledTimerWithTimeInterval: 0.1 target: self selector: @selector(timerTick:) userInfo: nil repeats:YES];
    [self.attacks removeAllObjects];
    [self.alertLabel setStringValue: @"started capture"];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char filename[] = "14pcap.pcap";
        [self.analyzer analyze: filename];
    });
}

#pragma mark - Timer

- (void)timerTick:(NSTimer *)timer
{
    // Timers are not guaranteed to tick at the nominal rate specified, so this isn't technically accurate.
    // However, this is just an example to demonstrate how to stop some ongoing activity, so we can live with that inaccuracy.
    _ticks += 0.1;
    double seconds = fmod(_ticks, 60.0);
    double minutes = fmod(trunc(_ticks / 60.0), 60.0);
    double hours = trunc(_ticks / 3600.0);
    [self.progressIndicator setDoubleValue:[PCAPAnalyzer progress] * 100.0];
    [self.timerLabel setStringValue: [NSString stringWithFormat: @"%02.0f:%02.0f:%04.1f", hours, minutes, seconds]];
}


@end
