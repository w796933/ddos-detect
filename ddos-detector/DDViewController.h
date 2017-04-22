//
//  DDViewController.h
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <MapKit/MapKit.h>

@interface DDViewController : NSViewController<NSTableViewDelegate, NSTableViewDataSource, MKMapViewDelegate>

@property (weak) IBOutlet NSTextField *alertLabel;
@property (weak) IBOutlet NSTableView *tableView;
@property (weak) IBOutlet NSProgressIndicator *progressIndicator;
@property (weak) IBOutlet NSTextField *timerLabel;
@property (weak) IBOutlet NSButton *alertButton;
@property (weak) IBOutlet MKMapView *mapView;

@end

