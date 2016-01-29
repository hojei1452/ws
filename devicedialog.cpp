#include "devicedialog.h"
#include "ui_devicedialog.h"

DeviceDialog::DeviceDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceDialog)
{
    ui->setupUi(this);

    devhandle = NULL;
    showallDev();
}

DeviceDialog::~DeviceDialog()
{
    delete ui;
}

void DeviceDialog::showallDev()
{
    if(pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
    {
        qDebug() << "pcap_findalldevs() error : " << errbuf;
        QMessageBox::information(NULL, "ERROR", "pcap_findalldevs() error");
        close();
    }

    int i;
    QListWidgetItem *qListWidgetItem;
    for(devsTmp = alldevs, i = 1; NULL != devsTmp; devsTmp = devsTmp->next, i++)
    {
        if(i == 1 && devsTmp == NULL)
        {
            qDebug() << "Interface not found!";
            QMessageBox::information(NULL, "ERROR", "Interface not found");
            close();
        }

        qListWidgetItem = new QListWidgetItem(ui->listWidget);
        qListWidgetItem->setText(devsTmp->name);
    }
    pcap_freealldevs(alldevs);
}

void DeviceDialog::choiceDev()
{
    QListWidgetItem *qListWidgetItem = new QListWidgetItem(ui->listWidget);
    qListWidgetItem = ui->listWidget->currentItem();

    confingName = qListWidgetItem->text();
    const char* devName = qListWidgetItem->text().toStdString().c_str();
    devhandle = pcap_open_live(devName, PCAP_READABLE_SIZE, PCAP_OPENFLAG_PROMISCUOUS, -1, errbuf);
    if(devhandle == NULL)
    {
        qDebug() << "Unable to open the adapter. This Device is not supported by pcap";
        QMessageBox::information(NULL, "Error", "Unable to open the adapter. \nThis Device is not supported by pcap");
        close();
    }
    else
        qDebug() << "Get device handel : " << devhandle;
}

void DeviceDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QPushButton* pushButton = (QPushButton*)button;
    if(pushButton == ui->buttonBox->button(QDialogButtonBox::Ok))
    {
        choiceDev();
    }
    else
        return;
}
