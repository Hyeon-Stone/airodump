#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "hdr.h"
#include "parse.h"
void usage() {
    printf("syntax: airodump <interface> \n");
    printf("sample: airodump mon0 \n");
}

int main(int argc, char* argv[]){

    if (argc < 2) {
            usage();
            return -1;
    }

    Parse(argv);
}
