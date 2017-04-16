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
    NSMutableSet *sourceIps;
    time_t startTime;
    time_t endTime;
    u_int numPackets;
};

typedef struct DDOSAttack ddos_t;

static NSString *attackDetectedEvent = @"DDOSAttackDetected";
static const u_int THRESHOLD = 10;
static id _thisClass;

@interface PCAPAnalyzer ()

@property (nonatomic, retain) NSMutableDictionary *ddosMap;

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
        
        cout << sourceIp << " >> " << destIp << " @ " << pkthdr->ts.tv_sec << endl;

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
        [_ddosMap setObject:[self cStructToObjc:attack] forKey:destIp];
    } else {
        DDOSAttack da = [self objcToStruct: [_ddosMap valueForKey:destIp]];
        if (da.startTime == attack.startTime) {
            da.numPackets++; // still the same second
            [da.sourceIps addObject:[[attack.sourceIps allObjects] objectAtIndex:0]];
            da.protocol = da.protocol != attack.protocol ? attack.protocol : da.protocol;
        } else { // count number of packets per second
            if (da.numPackets == THRESHOLD) {
                cout << ">>>>>>>>>>>>>>>>>>>>>>>>>> RED ALERT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << endl;
                NSDictionary *dictionary = [NSDictionary dictionaryWithObject: [self cStructToObjc: da] forKey:@"attack"];
                [[NSNotificationCenter defaultCenter] postNotificationName: attackDetectedEvent object: self userInfo: dictionary];
            }
            da.protocol = attack.protocol;
            da.startTime = attack.startTime;
            da.endTime = attack.endTime;
            da.numPackets = 1;
            [da.sourceIps removeAllObjects];
        }
        // re-populate
        [_ddosMap setObject:[self cStructToObjc:attack] forKey:destIp];
    }
}

- (DDOSAttack)objcToStruct: (NSValue *) val {
    // cast back to C struct (convert to struct pointer, then dereference)
    DDOSAttack attack;

    [val getValue: &attack];

    return attack;
}

- (NSValue *)cStructToObjc: (DDOSAttack) attack {
    return [NSValue valueWithBytes:&attack objCType:@encode(ddos_t)];
}

@end
