#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <curses.h>
#include <unistd.h>
#include <string.h>
#include "hdr.h"
#include "parse.h"
#include "print.h"
//#include <setjmp.h>
//#define TRY do{ jmp_buf ex_buf__; if( !setjmp(ex_buf__) ){
//#define CATCH } else {
//#define ETRY } }while(0)
//#define THROW longjmp(ex_buf__, 1)

#define TAG_OFFSET 2
void Parse(char** argv){
    initscr();
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
       fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
       exit(-1);
    }
    struct pcap_pkthdr* header;
    const u_char* data;
    int diff_cnt = 0;
    char* mac = (char *)calloc(17,sizeof(char));
    char** mac_lst = (char **)malloc((diff_cnt+1)*sizeof(char*));
    for (int i = 0; i<diff_cnt+1; i++)
        mac_lst[i] = (char*)calloc(17,sizeof(char));
    int* beacon_num = (int*)calloc(diff_cnt+1,sizeof(int));
    int* data_num = (int*)calloc(diff_cnt+1,sizeof(int));

    while(1){
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        uint16_t RadioTap_Len = Capture_RadioTap(data,RADIOTAP_LEN);
        int bssid = Check_Beacon(data,RadioTap_Len); //CHECK Beacon
        if (bssid == 0)
            continue;
        else{
            mac = Capture_BeaconorData(data,RadioTap_Len,bssid);
            int check = 1;
            int x = 1;
            for(x; x<=diff_cnt; x++){
                if(strncmp(mac_lst[x],mac,17) == 0){
                    if(bssid != 1)
                        data_num[x]++;
                    else
                        beacon_num[x]++;
                    check = 0;
                    break;
                }
            }
            if(check == 1){
                diff_cnt++;
                char** tempmac_lst = (char**)realloc(mac_lst,sizeof(char*)*(diff_cnt+1));
                mac_lst = tempmac_lst;
                mac_lst[diff_cnt] = (char*)calloc(17,sizeof(char));
                int* tempbeacon_num = (int*)realloc(beacon_num,sizeof(int)*(diff_cnt+1));
                beacon_num = tempbeacon_num;
                int* tempdata_num = (int*)realloc(data_num,sizeof(int)*(diff_cnt+1));
                data_num = tempdata_num;
                strncpy(mac_lst[diff_cnt],mac,17);
                if(bssid != 1){
                    data_num[diff_cnt] = 1;
                    beacon_num[diff_cnt] = 0;
                }
                else{
                    data_num[diff_cnt] = 0;
                    beacon_num[diff_cnt] = 1;
                }
            }
            move(0,0);
            printw("      BSSID\t\t   ESSID\tChannel\tENC\tBEACON\t#DATA\t");
            if(check==1){
                move(diff_cnt,0);
            }
            else{
                move(x,0);
            }
            printw("%s\t",mac_lst[x]);
            if(bssid == 1){
                Capture_Wireless(data,RadioTap_Len); //ESSID
                if(check ==1)
                    move(diff_cnt,50);
                else
                    move(x,40);
                Find_Tag(data,RadioTap_Len,CHANNEL);
//                TRY{
//                    Find_Tag(data,RadioTap_Len,ENC);
//                    THROW;
//                }
//                CATCH
//                {
//                    printw("WPAX");
//                    refresh();
//                    continue;
//                }
//                ETRY;
                printw("%4d\t", beacon_num[x]);
                printw("%4d\n", data_num[x]);

            }
            usleep(10000);
            refresh();
        }
    }
    free(data_num);
    free(beacon_num);
    for(diff_cnt; diff_cnt >=0; diff_cnt--)
        free(mac_lst[diff_cnt]);
    free(*mac_lst);
    free(mac);
    free(handle);

}

uint16_t Capture_RadioTap(const u_char* data, int option){
    RadioTap* capture = (RadioTap*)data;
    if (option == 0)
        return capture->len;
    else if(option == 1)
        return getbit(capture->present,DATA_RETRIES);
}

int Check_Beacon(const u_char* data, uint16_t len){
    Beacon* beacon = (Beacon*)(data+len);
    if (beacon->type == 0x80){
        return 1;
    }
    else if((beacon->type & 0xFF00) == 0x4100) // data flag TC
        return 3;
    else if((beacon->type & 0xFF00) == 0x4200 || (beacon->type & 0xFF00) == 0x6200) // data flag FC
        return 2;
    else
        return 0;
}
char* Capture_BeaconorData(const u_char* data, uint16_t len, int bssid){
    char* temp_mac = (char *)malloc(17*sizeof(char));
    if (bssid == 2){
        TC* tc = (TC*)(data+len);
        sprintf(temp_mac,"%02x:%02x:%02x:%02x:%02x:%02x",tc->BSSID[0], tc->BSSID[1],tc->BSSID[2],tc->BSSID[3],tc->BSSID[4],tc->BSSID[5]);
        return temp_mac;
    }
    else if(bssid == 3){
        FC* fc = (FC*)(data+len);
        sprintf(temp_mac,"%02x:%02x:%02x:%02x:%02x:%02x",fc->BSSID[0], fc->BSSID[1],fc->BSSID[2],fc->BSSID[3],fc->BSSID[4],fc->BSSID[5]);
        return temp_mac;
    }
    else{
        Beacon* beacon = (Beacon*)(data+len);
        sprintf(temp_mac,"%02x:%02x:%02x:%02x:%02x:%02x",beacon->BSSID[0], beacon->BSSID[1],beacon->BSSID[2],beacon->BSSID[3],beacon->BSSID[4],beacon->BSSID[5]);
        return temp_mac;
    }

}
void Capture_Wireless(const u_char* data, uint16_t len){
    int Beacon_Len = 24;
    int SSID_Offset = Beacon_Len +12 + TAG_OFFSET;
    Wireless* wireless = (Wireless*)(data+len+Beacon_Len);
    for(int i=0; i< wireless->tag_len; i++){
            printw("%c",*(data+len+SSID_Offset+i));
    }
    printw("\t");
}

void Find_Tag(const u_char* data, uint16_t len, int option){
    int Beacon_Len = 24;
    int SSID_Offset = Beacon_Len +12 + TAG_OFFSET;
    Wireless* wireless = (Wireless*)(data+len+Beacon_Len);
    int Offset = 0;
    tag* temp_tag = (tag*)(data+len+SSID_Offset + wireless->tag_len);

    while(true){
        Offset += TAG_OFFSET + temp_tag->tag_len;
        temp_tag = (tag*)(data+len+SSID_Offset + wireless->tag_len+Offset);
        if ((temp_tag->tag_num == 0xdd) && (option == ENC)){ // ENC
            if(*(data+len+SSID_Offset + wireless->tag_len+Offset+TAG_OFFSET+3) == 1){ // IF WPA 1
                printw("WPA%d\t",*(data+len+SSID_Offset + wireless->tag_len+Offset+TAG_OFFSET+4));
                break;
            }
            else if(*(data+len+SSID_Offset + wireless->tag_len+Offset+TAG_OFFSET+3) == 4){ //IF WPA 2
                printw("WPA%d\t",*(data+len+SSID_Offset + wireless->tag_len+Offset+TAG_OFFSET+11+2));
                break;
            }
        }
        else if((temp_tag->tag_num == 0x03) && (option == CHANNEL)){
            printw("%4d\t",*(data+len+SSID_Offset + wireless->tag_len + Offset+TAG_OFFSET));
            break;
        }
    }
}

int getbit(uint32_t x, int n){
    if (x & (1 << (n)))
        return 1;
    else
        return 0;
}
