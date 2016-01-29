#ifndef DEVICEDIALOG_H
#define DEVICEDIALOG_H

#include <QDialog>
#include <QMessageBox>
#include <QDebug>
#include <QListWidgetItem>
#include <pcap.h>
#include <QPushButton>

#define PCAP_READABLE_SIZE 65536
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_OPENFLAG_NON_PROMISCUOUS 0

namespace Ui {
class DeviceDialog;
}

class DeviceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceDialog(QWidget *parent = 0);
    ~DeviceDialog();

    pcap_t* devhandle;
    QString confingName;

private:
    Ui::DeviceDialog *ui;

    pcap_if_t* alldevs;
    pcap_if_t* devsTmp;
    char errbuf[PCAP_ERRBUF_SIZE];

protected:
    void showallDev();
    void choiceDev();

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);
};

#endif // DEVICEDIALOG_H
