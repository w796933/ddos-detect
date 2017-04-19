//
//  PCAPAnalyzer.m
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "PCAPAnalyzer.h"
#import "DDViewController.h"
#import "OrderedDictionary.h"

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

typedef NSMutableDictionary DDAttack;
typedef NSMutableDictionary DDPair;
typedef NSHashTable DDUniquePairs;
typedef NSMapTable DDUniquePairsWithPackets;

typedef struct DDOSAttack {
    int protocol;
    NSMutableSet *sourceIps;
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
static const u_int INTERVAL = 600; // 5 min
static const u_int MAP_MAX_SIZE = 100000;
static double progress = 0;
static u_int counter = 0;
static off_t fSize;
static time_t startT;
static time_t endT;

@interface PCAPAnalyzer ()

@property (nonatomic, retain) NSMutableArray<DDAttack *> *suspectAttacks;
@property (nonatomic, retain) NSMutableSet<DDAttack *> *actualAttacks;
@property (nonatomic) map<string, ddos_t> hm;
@property (nonatomic) LeastCount least;

@end

@implementation PCAPAnalyzer

off_t fsize(const char *filename) {
    struct stat st;
    
    if (stat(filename, &st) == 0)
        return st.st_size;
    
    return -1;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        __self = self;
        _suspectAttacks = [NSMutableArray new];
        _least = { .startTime = LONG_MAX, .numPackets = UINT_MAX, .destIp = "" };
    }
    return self;
}

+ (double) progress {
    return progress;
}

+ (time_t) startT {
    return startT;
}

+ (time_t) endT {
    return endT;
}

- (void) analyze: (char *)filename {
    progress = 0.0;
    [_suspectAttacks removeAllObjects];
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    fSize = fsize("14pcap.pcap");
    // open capture file for offline processing
    descr = pcap_open_offline(filename, errbuf);
    if (descr == NULL) {
        cout << "pcap_open_offline() failed: " << errbuf << endl;
        return;
    }
    
    cout << "starting capture" << endl;
    
    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return;
    }
    
    dispatch_async(dispatch_get_main_queue(),^{
        NSDictionary *dictionary = [NSDictionary dictionaryWithObject: self.suspectAttacks forKey: @"attacks"];
        [[NSNotificationCenter defaultCenter] postNotificationName: packetFinish object: nil userInfo: dictionary];
    });
    
    cout << "capture finished" << endl;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {;
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    DDOSAttack attack;
    attack.sourceIps = [NSMutableSet new];
    ethernetHeader = (struct ether_header*)packet;
    
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        
//        cout << sourceIp << " >> " << destIp << " @ " << pkthdr->ts.tv_sec << endl;
        
//        dispatch_async(dispatch_get_main_queue(),^{
//            globalPacketCounter++;
//            NSDictionary *dictionary = [NSDictionary dictionaryWithObject: [NSNumber numberWithUnsignedInteger:globalPacketCounter ] forKey: @"counter"];
//            [[NSNotificationCenter defaultCenter] postNotificationName: packetEvent object: nil userInfo: dictionary];
//        });

        if (counter == 0) startT = pkthdr->ts.tv_sec;
        endT = pkthdr->ts.tv_sec;
        
        counter++;
        double p = (((double)counter) + 1.0) / ((double)fSize);
        progress = p;
        
        attack.protocol = ipHeader->ip_p;
        [attack.sourceIps addObject: [NSString stringWithCString: sourceIp encoding: NSUTF8StringEncoding]];
        attack.startTime = pkthdr->ts.tv_sec;
        attack.endTime = pkthdr->ts.tv_sec;
        attack.numPackets = 1;
        
        // using an extra reference to self in order to call objc method
        [__self populateMap: attack destination: destIp];
    }
}

- (void) populateMap: (DDOSAttack) attack destination: (char *) destIp {
    string dest(destIp);
    // referecing property using self does not work, no idea why
    if (_hm.find(dest) == _hm.end()) {
        // SpaceSaving: replace oldest item with least count
        if (_hm.size() == MAP_MAX_SIZE) {
            _hm[_least.destIp] = attack;
        } else {
            // map still has space, we're good
            _hm[dest] = attack;
        }
    } else {
        DDOSAttack da = _hm[dest];
        if ((attack.startTime - da.startTime) <= INTERVAL) {
            da.numPackets++; // still the same second
            da.endTime = attack.startTime;
            [da.sourceIps addObject:[[attack.sourceIps allObjects] objectAtIndex:0]];
            da.protocol = da.protocol != attack.protocol ? attack.protocol : da.protocol;
        } else {
            if (da.numPackets >= THRESHOLD && (attack.startTime - da.startTime == (INTERVAL + 1))) {
                NSMutableDictionary *att = [self cStructToDict:da].mutableCopy;
                [att setObject: [NSString stringWithCString:destIp encoding:NSUTF8StringEncoding] forKey:@"destIp"];
                [self.suspectAttacks addObject:att];
            }
            da.protocol = attack.protocol;
            da.startTime = attack.startTime;
            da.endTime = attack.endTime;
            da.numPackets = 1;
            [da.sourceIps removeAllObjects];
            [da.sourceIps addObject:[[attack.sourceIps allObjects] objectAtIndex:0]];
        }
        // find the "least" element
        if (da.startTime < _least.startTime && da.numPackets < _least.numPackets) {
            _least = { .startTime = da.startTime, .numPackets = da.numPackets, .destIp = dest };
        }
        // re-populate
        _hm[dest] = da;
    }
}

- (NSDictionary *) cStructToDict: (DDOSAttack) attack {
    NSDictionary *dict = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                          [NSNumber numberWithInt: attack.protocol], @"protocol",
                          [NSNumber numberWithInt: attack.numPackets], @"numPackets",
                          [NSNumber numberWithLong: attack.startTime], @"startTime",
                          [NSNumber numberWithLong: attack.endTime], @"endTime",
                          attack.sourceIps, @"sourceIps",
                          nil];
    return dict;
}

- (void) filterAttacks: (NSArray *) attacks {
    NSMutableDictionary *timeline = [NSMutableDictionary new];
    u_long numPackThresh = 0;
    u_long ratio = 0;
    // find max pp10min
    for (DDAttack *attack in attacks) {
        NSNumber *time = ((NSNumber *)[attack objectForKey:@"endTime"]);
        if (timeline[time] == nil) {
            timeline[time] = [NSMutableArray new];
        }
        if (((NSNumber *)[attack objectForKey:@"numPackets"]).unsignedIntegerValue > numPackThresh) {
            numPackThresh = ((NSNumber *)[attack objectForKey:@"numPackets"]).unsignedIntegerValue;
        }
    }
    numPackThresh /= 2;
    ratio = (numPackThresh / 3) / 10;
    numPackThresh = (numPackThresh - numPackThresh % 10);
    ratio = (ratio - ratio % 10);
    for (DDAttack *attack in attacks) {
        NSString *timeString = ((NSNumber *)[attack objectForKey:@"endTime"]).stringValue;
        [((NSMutableArray *)timeline[timeString]) addObject:attack];
    }
//    NSString *timeString;
//    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
//    [dateFormat setDateFormat:@"MMM-dd-hh:mm"];
//    NSDate *date = [NSDate dateWithTimeIntervalSince1970:((NSNumber *)[attack objectForKey:@"endTime"]).unsignedIntegerValue];
//    timeString = [dateFormat stringFromDate:date];
    NSArray *sortedKeys = [[timeline allKeys] sortedArrayUsingSelector: @selector(caseInsensitiveCompare:)];
    NSArray *objects = [timeline objectsForKeys: sortedKeys notFoundMarker: [NSNull null]];
    for (int i = 0; i < sortedKeys.count; i++) {
        
    }
}

- (BOOL) attacksEqual: (DDAttack *)att1 with:(DDAttack *)att2 {
    BOOL destIp = [((NSString *)[att1 objectForKey:@"destIp"]) isEqualToString:((NSString *)[att2 objectForKey:@"destIp"])];
    NSSet<NSString *> *sources1 = (NSSet<NSString *> *)[att1 objectForKey:@"sourceIps"];
    NSSet<NSString *> *sources2 = (NSSet<NSString *> *)[att2 objectForKey:@"sourceIps"];
    BOOL sourceIp = [sources1 isEqualToSet:sources2];
    return destIp & sourceIp;
}


@end
