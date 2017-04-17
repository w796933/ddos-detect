//
//  PCAPAnalyzer.h
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#ifndef PCAPAnalyzer_h
#define PCAPAnalyzer_h

#import <Cocoa/Cocoa.h>

static NSString *attackDetectedEvent = @"DDOSAttackDetected";
static NSString *packetEvent = @"PacketReceived";
static NSString *packetFinish = @"PacketsFinished";

static id __Self;

@interface PCAPAnalyzer : NSObject

@property (weak, nonatomic) id delegate;

+ (double) progress;
- (void) analyze: (char *)filename;

@end


#endif /* PCAPAnalyzer_h */
