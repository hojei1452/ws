#ifndef SCANNER_H
#define SCANNER_H

#include <QDebug>
#include <QString>
#include <QChar>
#include <QObject>
#include <pcap.h>
#include <arpa/inet.h>

#define BIT(n) 1 << n

enum _encrypt
{
    IEEE80211_ENCRYPT_WPA2WPA,
    IEEE80211_ENCRYPT_WPA2,
    IEEE80211_ENCRYPT_WPA,
    IEEE80211_ENCRYPT_WEP,
    IEEE80211_NON_ENCRYPT,
    IEEE80211_UNKNOWN_ENCRYPT
};

#pragma pack(push, 1)
struct ScannerInfo
{
    QString SSID;
    QString BSSID;
    int Encrypt;
    QString StationAddr;
    int Channel;
    int Signal;
    const char* Data;
};

#define _6ByteSIZE 6

struct _6ByteArray
{
    u_int8_t value[_6ByteSIZE];
};

struct ieee80211_frame_format
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t type_or_subtype;
    u_int8_t frame_contral_field;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t frame_contral_field;
    u_int8_t type_or_subtype;
#endif
    u_int16_t duration;
#define ETH_LEN 6
    u_int8_t destination_address[ETH_LEN];  // + Receiver_address
    u_int8_t source_address[ETH_LEN];   // + Transmitter_address
    u_int8_t BSS_id[ETH_LEN];
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t fragment_number:4;
    u_int16_t sequence_number:12;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t sequence_number:12;
    u_int8_t fragment_number:4;
#endif
};

struct ieee80211_management_frame_fixed_parameters
{
    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t caoabilities_info;
};

#pragma pack(pop)

class Scanner : public QObject
{
    Q_OBJECT
public:
    explicit Scanner(QObject *parent = 0);
    void getHandle(pcap_t *);

    bool isRunning;

private:
    pcap_t* devhandle;
    pcap_pkthdr* header;
    const u_char* pkt_data;

protected:
    void getRadiotapInfo(const uchar *data, int8_t* signal, u_int16_t* channel_frequency);
    bool addPadding(int tLength)  {   return tLength % 2;   }
    void needPadding(int* thisPointer, size_t addPointer)
    {
        if(addPadding(*thisPointer))
            *thisPointer += addPointer + sizeof(u_int8_t);
        else
            *thisPointer += addPointer;
    }
    void needPadding(int* thisPointer)
    {
        if(addPadding(*thisPointer))
            *thisPointer += sizeof(u_int8_t);
    }
    QString u8byteToQString(u_int8_t* srcId);

signals:
    void addPackets();
    void captured(ScannerInfo info);
    void scannerError();

public slots:
    void doStart();
    void doStop()   {   this->isRunning = false;    }

};

#endif // SCANNER_H
