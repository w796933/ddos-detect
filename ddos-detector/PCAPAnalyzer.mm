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

typedef struct DDOSAttack {
    int protocol;
    NSMutableSet *sourceIps;
    time_t startTime;
    time_t endTime;
    u_int numPackets;
} ddos_t;

static const u_int THRESHOLD = 100;

@interface PCAPAnalyzer ()

@property (nonatomic, retain) NSMutableDictionary *ddosMap;
@property (nonatomic) map<string, ddos_t> hm;

@end

@implementation PCAPAnalyzer

- (instancetype)init
{
    self = [super init];
    if (self) {
        _thisClass = self;
        _ddosMap = [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (void) analyze {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // open capture file for offline processing
    descr = pcap_open_offline("dirtjumper.pcap", errbuf);
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
    attack.sourceIps = [[NSMutableSet alloc] init];
    ethernetHeader = (struct ether_header*)packet;
    
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        
        //cout << sourceIp << " >> " << destIp << " @ " << pkthdr->ts.tv_sec << endl;

        attack.protocol = ipHeader->ip_p;
        [attack.sourceIps addObject: [NSString stringWithCString: sourceIp encoding: NSASCIIStringEncoding]];
        attack.startTime = pkthdr->ts.tv_sec;
        attack.endTime = pkthdr->ts.tv_sec;
        attack.numPackets = 1;
        
        string dest(destIp);
        // this should be illegal
        [_thisClass populateMap: attack destination: destIp];
    }
}

- (void) populateMap: (DDOSAttack) attack destination: (char *) destIp {
    string dest(destIp);
    if (_hm.find(dest) == _hm.end()) {
        _hm[dest] = attack;
    } else {
        DDOSAttack da = _hm[dest];
        if (da.startTime == attack.startTime) {
            da.numPackets++; // still the same second
            [da.sourceIps addObject:[[attack.sourceIps allObjects] objectAtIndex:0]];
            da.protocol = da.protocol != attack.protocol ? attack.protocol : da.protocol;
        } else {
            if (da.numPackets >= THRESHOLD && (attack.startTime - da.startTime == 1)) {
                cout << " >> " << destIp << " @ " << da.startTime << endl;
                NSMutableDictionary *att = [self cStructToDict:da].mutableCopy;
                [att setObject: [NSString stringWithCString:destIp encoding:NSUTF8StringEncoding] forKey:@"destIp"];
                NSDictionary *dictionary = [NSDictionary dictionaryWithObject: att forKey: @"attack"];
                [[NSNotificationCenter defaultCenter] postNotificationName: attackDetectedEvent object: nil userInfo: dictionary];
            }
            da.protocol = attack.protocol;
            da.startTime = attack.startTime;
            da.endTime = attack.endTime; // you don't really need end time...we are concerned with 1 sec periods only
            da.numPackets = 1;
            [da.sourceIps removeAllObjects];
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
