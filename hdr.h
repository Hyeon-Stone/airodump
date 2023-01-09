#include <stdint.h>
#pragma pack(push,1)
typedef struct{
    uint8_t reversion;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
}RadioTap;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    uint16_t type;
    uint16_t padding;
    uint8_t des_mac[6];
    uint8_t src_mac[6];
    uint8_t BSSID[6];
    uint16_t seq_num;
}Beacon;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    uint16_t type;
    uint16_t padding;
    uint8_t BSSID[6];
}FC;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    uint16_t type;
    uint16_t padding;
    uint8_t recv_mac[6];
    uint8_t BSSID[6];
}TC;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    uint8_t timestamp[8];
    uint16_t beacon_intv;
    uint16_t cap_info;
    uint8_t tag_num;
    uint8_t tag_len;
}Wireless;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct{
    uint8_t tag_num;
    uint8_t tag_len;
}tag;
enum radiotap_present {
    TSFT = 0,
    FLAGS = 1,
    RATE = 2,
    CHANNEL = 3,
    FHSS = 4,
    DBM_ANTSIGNAL = 5,
    DBM_ANTNOISE = 6,
    LOCK_QUALITY = 7,
    TX_ATTENUATION = 8,
    DB_TX_ATTENUATION = 9,
    DBM_TX_POWER = 10,
    ANTENNA = 11,
    DB_ANTSIGNAL = 12,
    DB_ANTNOISE = 13,
    RX_FLAGS = 14,
    TX_FLAGS = 15,
    RTS_RETRIES = 16,
    DATA_RETRIES = 17,
    /* 18 is XChannel, but it's not defined yet */
    MCS = 19,
    AMPDU_STATUS = 20,
    VHT = 21,
    TIMESTAMP = 22,
    /* valid in every it_present bitmap, even vendor namespaces */
    RADIOTAP_NAMESPACE = 29,
    VENDOR_NAMESPACE = 30,
    EXT = 31
};
