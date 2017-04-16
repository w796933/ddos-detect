//
//  PCAPAnalyzer.m
//  ddos-detector
//
//  Created by Joanna Bitton on 4/15/17.
//  Copyright © 2017 Joanna Bitton. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PCAPAnalyzer.h"

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

using namespace std;

struct DDOSAttack {
    int protocol;
    NSMutableArray<NSString *> *sourceIps;
    time_t startTime;
    time_t endTime;
    u_int numPackets;
};

static const u_int THRESHOLD = 35000;

id _thisClass;

@interface PCAPAnalyzer ()

@property (nonatomic, retain) NSMutableDictionary *ddosMap;

@end

@implementation PCAPAnalyzer

- (instancetype)init
{
    self = [super init];
    if (self) {
        _thisClass = self;
    }
    return self;
}

- (void) analyze {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // open capture file for offline processing
    descr = pcap_open_offline("14pcap.pcap", errbuf);
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
    
    cout << "capture finished" << endl;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    DDOSAttack attack;
    
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        
        attack.protocol = ipHeader->ip_p;
        [attack.sourceIps addObject: [NSString stringWithCString: sourceIp encoding: NSASCIIStringEncoding]];
        attack.startTime = pkthdr->ts.tv_sec;
        attack.endTime = pkthdr->ts.tv_sec;
        attack.numPackets = 1;
        [_thisClass populateMap: attack destination: [NSString stringWithCString: destIp encoding: NSUTF8StringEncoding]];
        
    }
}

- (void) populateMap: (DDOSAttack) attack destination: (NSString *) destIp {
    if ([_ddosMap objectForKey:destIp] == nil) {
        NSValue *NSAttack = [NSValue value: &attack
                             withObjCType:@encode(DDOSAttack)];
        [_ddosMap insertValue: NSAttack inPropertyWithKey:destIp];
    } else {
        
    }
}

@end
