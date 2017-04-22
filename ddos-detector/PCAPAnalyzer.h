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
#import "DDViewController.h"

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/stat.h>

using namespace std;

#pragma mark - typedef

typedef void (^FilterBlock)(NSMutableSet *_Nonnull result);

typedef NSMutableDictionary DDAttack;
typedef NSMutableDictionary DDPair;
typedef NSMutableDictionary DDUniquePairsMap;

typedef struct DDOSAttack {
    int protocol;
    NSMutableSet * _Nonnull sourceIps;
    time_t startTime;
    time_t endTime;
    u_int numPackets;
} ddos_t;

typedef struct LeastCount {
    u_int numPackets;
    time_t startTime;
    string destIp;
} count_t;

#pragma mark - Globals

static const u_int THRESHOLD = 1000;
static const u_int MIN_PACKETS_PER_HOUR = 6;
static const u_int INTERVAL = 600; // 10 min
static const u_int MAP_MAX_SIZE = 1000000;

static double_t progress = 0;
static u_int counter = 0;
static off_t fSize;
static time_t startT;
static time_t endT;

static NSString * _Nonnull const attackDetectedEvent = @"AttackDetected";
static NSString * _Nonnull const packetEvent = @"PacketReceived";
static NSString * _Nonnull const packetFinish = @"PacketsFinished";
static NSString * _Nonnull const filterFinish = @"FilteringFinished";

__weak static id _Nullable __self;

@interface PCAPAnalyzer : NSObject

+ (time_t) startT;
+ (time_t) endT;
+ (double) progress;
+ (void) resetProgress;
- (void) analyze: (char *_Nonnull)filename;
- (void) filterAttacks: (NSArray *_Nonnull)attacks completion: (FilterBlock _Nonnull)block;

@end


#endif /* PCAPAnalyzer_h */
