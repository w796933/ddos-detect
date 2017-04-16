#import "ViewController.h"
#import "PCAPAnalyzer.h"

#include <iostream>

using namespace std;

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    PCAPAnalyzer *analyzer = [[PCAPAnalyzer alloc] init];
    [analyzer analyze];
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}


@end
