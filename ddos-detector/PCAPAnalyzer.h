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
static id _thisClass;

@interface PCAPAnalyzer : NSObject

- (void) analyze;

@end


#endif /* PCAPAnalyzer_h */
