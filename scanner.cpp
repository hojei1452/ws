#include "scanner.h"
#include "ieee80211_radiotap.h"

Scanner::Scanner(QObject *parent) : QObject(parent)
{
    isRunning = false;
}

void Scanner::getHandle(pcap_t* handle)
{
    devhandle = handle;
}

void Scanner::doStart()
{
    while(isRunning)
    {
        int res = pcap_next_ex(devhandle, &header, &pkt_data);
        if(res == 0)
            continue;
        else if(res < 0)
        {
            //error
            break;
        }

        emit addPackets();

        ScannerInfo scannerInfo;
        ieee80211_radiotap_header* pRadiotaph = (struct ieee80211_radiotap_header *)pkt_data;
        int Current_len = 0;

        if(pRadiotaph->it_version != 0x00)
            continue;

        int8_t signal = 0;
        u_int16_t channel = 0;
        getRadiotapInfo(pkt_data, &signal, &channel);
        scannerInfo.Signal = signal;
        scannerInfo.Channel = ((int)channel - 2407) / 5;

        Current_len = pRadiotaph->it_len;
        u_int16_t frameType = *((u_int16_t*)(pkt_data + Current_len));
        frameType = ntohs(frameType);

        // 'Beacon frame(0x8000)' or 'Probe Response frame(0x5008)' or 'Data frame'
        if(frameType == 0x8000 || frameType == 0x5008 || frameType & BIT(11))
        {
            ieee80211_frame_format* pFrames = (struct ieee80211_frame_format *)(pkt_data + pRadiotaph->it_len);

            if((pFrames->frame_contral_field & BIT(3))) // Re-transmitted
                continue;

            scannerInfo.BSSID = u8byteToQString(pFrames->BSS_id);

            if(frameType & BIT(11))  // Data frame
            {
                if(frameType & BIT(14))  // No data frame
                    continue;
                // 10 (APstation -> Mobile)
                if((pFrames->frame_contral_field & BIT(1)) && !(pFrames->frame_contral_field & BIT(0)))
                {
                    scannerInfo.StationAddr = u8byteToQString(pFrames->destination_address);
                    scannerInfo.BSSID = u8byteToQString(pFrames->source_address);
                }
                // 01 (Mobile -> APstation)
                else if(!(pFrames->frame_contral_field & BIT(1)) && (pFrames->frame_contral_field & BIT(0)))
                {
                    scannerInfo.StationAddr = u8byteToQString(pFrames->source_address);
                    scannerInfo.BSSID = u8byteToQString(pFrames->destination_address);
                }
                else
                    continue;

                if(frameType & BIT(15)) // QoS Data
                {
                    Current_len = sizeof(struct ieee80211_frame_format) + pRadiotaph->it_len;
                    Current_len += sizeof(u_int16_t);   // QoS Control
                    Current_len += sizeof(u_int64_t);   // CCMP Parameters

                    scannerInfo.Data = (const char *)(pkt_data + Current_len);
                }
            }
            else // 'Beacon frmae' or 'Probe Response frame'
            {
                Current_len = sizeof(struct ieee80211_frame_format) + pRadiotaph->it_len;
                Current_len += sizeof(struct ieee80211_management_frame_fixed_parameters);

                scannerInfo.Encrypt = IEEE80211_UNKNOWN_ENCRYPT;
                while(Current_len < (int)header->len)
                {
                    u_int8_t parameterSet = *((u_int8_t*)(pkt_data + Current_len));
                    Current_len += sizeof(u_int8_t);

                    u_int8_t parameterSize = *((u_int8_t*)(pkt_data + Current_len));
                    Current_len += sizeof(u_int8_t);

                    if((int)parameterSet == 0)
                    {
                        if((int)parameterSize != 0)
                        {
                            u_int8_t ssidCheck = *((u_int8_t*)(pkt_data + Current_len));
                            if(ssidCheck != 0x00 && ssidCheck >= 0x20 && ssidCheck <= 0x7e)
                            {
                                QString ssID = QString("%1").arg((char*)pkt_data + Current_len);
                                ssID.resize((int)parameterSize);
                                scannerInfo.SSID = ssID;
                            }
                        }
                    }
                    else if((int)parameterSet == 3)
                    {
                        u_int8_t _channel = *((u_int8_t*)(pkt_data + Current_len));
                        if(scannerInfo.Channel != _channel)
                            scannerInfo.Channel = _channel;
                    }
                    else if((int)parameterSet == 48)
                    {
                        if(scannerInfo.Encrypt == IEEE80211_ENCRYPT_WPA)
                            scannerInfo.Encrypt = IEEE80211_ENCRYPT_WPA2WPA;
                        else
                            scannerInfo.Encrypt = IEEE80211_ENCRYPT_WPA2;
                    }
                    else if((int)parameterSet == 221)
                    {
                        _6ByteArray* _checkParameter = (struct _6ByteArray*)(pkt_data + Current_len);
                        QString checkParameter = u8byteToQString(_checkParameter->value);
                        if(checkParameter.contains(QString("00:50:F2:01:01:00")))
                        {
                            if(scannerInfo.Encrypt == IEEE80211_ENCRYPT_WPA2)
                                scannerInfo.Encrypt = IEEE80211_ENCRYPT_WPA2WPA;
                            else
                                scannerInfo.Encrypt = IEEE80211_ENCRYPT_WPA;
                        }
                    }
                    if((int)parameterSize != 0)
                        Current_len += (int)parameterSize;
                }
                ieee80211_management_frame_fixed_parameters* pManfixedParamter =
                        (struct ieee80211_management_frame_fixed_parameters *)(pkt_data + (sizeof(struct ieee80211_frame_format) + pRadiotaph->it_len));
                if((pManfixedParamter->caoabilities_info & BIT(4)) && scannerInfo.Encrypt == IEEE80211_UNKNOWN_ENCRYPT)    // Encrypt is WEP
                    scannerInfo.Encrypt = IEEE80211_ENCRYPT_WEP;
                if(scannerInfo.Encrypt == IEEE80211_UNKNOWN_ENCRYPT)
                    scannerInfo.Encrypt = IEEE80211_NON_ENCRYPT;
            }
        }
        emit captured(scannerInfo);
    }
    emit scannerError();
}

void Scanner::getRadiotapInfo(const uchar *data, int8_t* signal, u_int16_t* channel_frequency)
{
    ieee80211_radiotap_header* pRadiotaph = (struct ieee80211_radiotap_header*)data;
    int dataPointer = sizeof(struct ieee80211_radiotap_header);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_EXT))
        dataPointer += (sizeof(u_int32_t) * 2);

    isflag:
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_TSFT))
        dataPointer += sizeof(u_int64_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_FLAGS))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_RATE))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_CHANNEL))
    {
        needPadding(&dataPointer);
        *channel_frequency = *((u_int16_t*)(data + dataPointer));
        dataPointer += (sizeof(u_int16_t) * 2);
    }
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_FHSS))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
    {
        if(*signal == 0)
            *signal = *((int8_t*)(data + dataPointer));
        else
        {
            int8_t signal2 = *((int8_t*)(data + dataPointer));
            *signal = (*signal + signal2) / 2;
        }
        dataPointer += sizeof(int8_t);

        if(!(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_EXT)))
            return;
    }
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DBM_ANTNOISE))
        dataPointer += sizeof(int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_LOCK_QUALITY))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_TX_ATTENUATION))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DB_TX_ATTENUATION))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DBM_TX_POWER))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_ANTENNA))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DB_ANTSIGNAL))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DB_ANTNOISE))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_RX_FLAGS))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_TX_FLAGS))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_RTS_RETRIES))
        dataPointer += sizeof(u_int8_t);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_DATA_RETRIES))
        dataPointer += sizeof(u_int8_t);
    // find case
//    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_MCS))
//        dataPointer += (sizeof(u_int8_t) * 3);
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_MCS))
        needPadding(&dataPointer, sizeof(u_int16_t));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_AMPDU_STATUS))
        needPadding(&dataPointer, sizeof(u_int32_t) + sizeof(u_int16_t) + (sizeof(u_int8_t) * 2));
    if(pRadiotaph->it_present & BIT(IEEE80211_RADIOTAP_VHT))
        needPadding(&dataPointer, (sizeof(u_int16_t) * 2) + (sizeof(u_int8_t) * 8));

    int i = 0;
    pRadiotaph->it_present = *((u_int32_t*)(data + (sizeof(struct ieee80211_radiotap_header) + i)));
    i += sizeof(u_int32_t);
    goto isflag;
}

QString Scanner::u8byteToQString(u_int8_t* srcId)
{
    uint8_t ch1, ch2;
    int i, index;
    char buf[_6ByteSIZE * 3];

    index = 0;
    for (i = 0; i < _6ByteSIZE; i++)
    {
        ch1 = srcId[i] & 0xF0;
        ch1 = ch1 >> 4;
        if (ch1 > 9)
            ch1 = ch1 + 'A' - 10;
        else
            ch1 = ch1 + '0';
        ch2 = srcId[i] & 0x0F;
        if (ch2 > 9)
            ch2 = ch2 + 'A' - 10;
        else
            ch2 = ch2 + '0';
        buf[index++] = ch1;
        buf[index++] = ch2;
        buf[index++] = ':';
    }
    buf[--index] = '\0';
    return (QString(buf));
}
