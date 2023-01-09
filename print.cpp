#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>
void PrintMAC(char* msg, uint8_t *mac){
    printf("| %s | %02x:%02x:%02x:%02x:%02x:%02x |\n", msg, mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
}
