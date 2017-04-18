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

typedef NSDictionary NSAttack;

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

static const u_int THRESHOLD = 100;
static const u_int MAP_MAX_SIZE = 100000;
static double progress = 0;
static u_int counter = 0;
static off_t fSize;

@interface PCAPAnalyzer ()

@property (atomic, retain) NSMutableArray<NSAttack *> *attacks;
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
        __Self = self;
        _attacks = [NSMutableArray new];
        _least = { .startTime = LONG_MAX, .numPackets = UINT_MAX, .destIp = "" };
    }
    return self;
}

+ (double) progress {
    return progress;
}

- (void) analyze: (char *)filename {
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
        NSDictionary *dictionary = [NSDictionary dictionaryWithObject: self.attacks forKey: @"attacks"];
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
    attack.sourceIps = [[NSMutableSet alloc] init];
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

        counter++;
        double p = (((double)counter) + 1.0) / ((double)fSize);
        progress = p;
        
        attack.protocol = ipHeader->ip_p;
        [attack.sourceIps addObject: [NSString stringWithCString: sourceIp encoding: NSUTF8StringEncoding]];
        attack.startTime = pkthdr->ts.tv_sec;
        attack.endTime = pkthdr->ts.tv_sec;
        attack.numPackets = 1;
        
        // using an extra reference to self in order to call objc method
        [__Self populateMap: attack destination: destIp];
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
        if (da.startTime == attack.startTime) {
            da.numPackets++; // still the same second
            [da.sourceIps addObject:[[attack.sourceIps allObjects] objectAtIndex:0]];
            da.protocol = da.protocol != attack.protocol ? attack.protocol : da.protocol;
        } else {
            if (da.numPackets >= THRESHOLD && (attack.startTime - da.startTime == 1)) {
                NSMutableDictionary *att = [self cStructToDict:da].mutableCopy;
                [att setObject: [NSString stringWithCString:destIp encoding:NSUTF8StringEncoding] forKey:@"destIp"];
                [self.attacks addObject:att];
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

@end
