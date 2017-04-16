#ifndef PCAPAnalyzer_h
#define PCAPAnalyzer_h

#import <Cocoa/Cocoa.h>

static NSString *attackDetectedEvent = @"DDOSAttackDetected";
static id _thisClass;

@interface PCAPAnalyzer : NSObject

- (void) analyze;

@end


#endif /* PCAPAnalyzer_h */
