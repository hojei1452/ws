#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);

    ui->ScannerTreeWidget->setColumnWidth(2, 89);
    ui->ScannerTreeWidget->setColumnWidth(3, 65);
    ui->ScannerTreeWidget->setColumnWidth(4, 55);
    ui->ScannerTreeWidget->setColumnWidth(5, 65);
    ui->ScannerTreeWidget->setColumnWidth(6, 65);

    ui->StatuLabel->setText("Stopped");
    ui->ChannelLabel->setText("Channel : 1");

    ui->ScannerTreeWidget->sortByColumn(SCANNER_COLUMN_CHANNEL, Qt::AscendingOrder);
    ui->ScannerTreeWidget->setSortingEnabled(true);

    ui->ScannetrabWidget->setCurrentIndex(0);

    QObject::connect(&scannerThread, SIGNAL(started()), &scanner, SLOT(doStart()));
    QObject::connect(&scanner, SIGNAL(captured(ScannerInfo)), this, SLOT(set_captureItem(ScannerInfo)), Qt::BlockingQueuedConnection);
    QObject::connect(&scanner, SIGNAL(addPackets()), this, SLOT(addPacket()));
    QObject::connect(&scanner, SIGNAL(scannerError()), &scannerThread, SLOT(terminate()));
    QObject::connect(&scannerThread, SIGNAL(finished()), &scanner, SLOT(doStop()));

    QObject::connect(&timerThread, SIGNAL(started()), &timer, SLOT(start()));
    QObject::connect(&timer, SIGNAL(timeout()), this, SLOT(changeInfo()));
    QObject::connect(&timerThread, SIGNAL(finished()), &timer, SLOT(stop()));
}

Widget::~Widget()
{
    delete ui;
}

void Widget::on_StartButton_clicked()
{
    if(ui->ScannetrabWidget->currentIndex() == 0)  // Scanner
    {
        DeviceDialog deviceDialog;
        deviceDialog.show();
        deviceDialog.exec();

        if(deviceDialog.devhandle != NULL && scanner.isRunning == false)
        {
            ui->ScannerTreeWidget->clear();
            devName = deviceDialog.confingName;

            if(devName.contains("dummy0"))
            {
                scanner.getHandle(deviceDialog.devhandle);
                scanner.isRunning = true;
                scanner.moveToThread(&scannerThread);
                scannerThread.start();
                ui->StatuLabel->setText("Running");
                return;
            }

            if(!isMonitor())
            {
                QMessageBox::information(NULL, "ERROR", "this device is not set moniter mode");
                qDebug() << "this device is not set moniter mode";
                return;
            }

            currentChannel = 0;
            packets = 0;

            scanner.getHandle(deviceDialog.devhandle);
            scanner.isRunning = true;
            scanner.moveToThread(&scannerThread);
            scannerThread.start();

            timer.setInterval(1000);
            timer.moveToThread(&timerThread);
            timerThread.start();

            ui->StatuLabel->setText("Running : 0packets/s");
        }
    }
    else if(ui->ScannetrabWidget->currentIndex() == 1) // analyzer
    {
    }
}

void Widget::on_StopButton_clicked()
{
    if(scanner.isRunning)
    {
        scanner.isRunning = false;
        scannerThread.quit();
        scannerThread.wait();
        timerThread.quit();
        timerThread.wait();

        ui->StatuLabel->setText("Stopped");
    }
}

void Widget::set_captureItem(ScannerInfo info)
{
    if(info.BSSID == NULL)
        return;

    QList<QTreeWidgetItem*> listItem = ui->ScannerTreeWidget->findItems(info.BSSID, Qt::MatchWildcard, SCANNER_COLUMN_BSSID);
    if(listItem.count() == 0)   // new AP
    {
        if(info.StationAddr != NULL || info.SSID == NULL || info.Channel == 0 || info.Signal == 0)
            return;

        QTreeWidgetItem* newItem = new QTreeWidgetItem(ui->ScannerTreeWidget);
        newItem->setText(SCANNER_COLUMN_SSID, info.SSID);
        newItem->setText(SCANNER_COLUMN_BSSID, info.BSSID);
        if(info.Encrypt == IEEE80211_ENCRYPT_WPA2)
            newItem->setText(SCANNER_COLUMN_ENCRTPT, QString("WPA2"));
        else if(info.Encrypt == IEEE80211_ENCRYPT_WPA)
            newItem->setText(SCANNER_COLUMN_ENCRTPT, QString("WPA"));
        else if(info.Encrypt == IEEE80211_ENCRYPT_WPA2WPA)
            newItem->setText(SCANNER_COLUMN_ENCRTPT, QString("WPA/WPA2"));
        else if(info.Encrypt == IEEE80211_ENCRYPT_WEP)
            newItem->setText(SCANNER_COLUMN_ENCRTPT, QString("WEP"));
        else if(info.Encrypt == IEEE80211_NON_ENCRYPT)
            newItem->setText(SCANNER_COLUMN_ENCRTPT, QString("OPEN"));
        //newItem->setText(SCANNER_COLUMN_CHANNEL, QString::number(info.Channel));
        newItem->setData(SCANNER_COLUMN_CHANNEL, Qt::DisplayRole, info.Channel);
        newItem->setText(SCANNER_COLUMN_SIGNAL, QString::number(info.Signal));
        newItem->setText(SCANNER_COLUMN_STATIONS, QString::number(0));
        newItem->setText(SCANNER_COLUMN_DATAS, QString::number(0));

    }
    else if(listItem.count() == 1)
    {
        if(info.Channel == 0 || info.Signal == 0)
            return;

        QTreeWidgetItem* currentItem = listItem[0];
        currentItem->setText(SCANNER_COLUMN_SIGNAL, QString::number(info.Signal));  // signal update

        if(info.StationAddr != NULL)    // data frame
        {
            if(info.StationAddr.contains(QString("01:00:5E"))
                    || info.StationAddr.contains(QString("33:33:FF"))
                    || info.StationAddr.contains(QString("33:33:00"))
                    || info.StationAddr.contains(QString("01:80:C2:00:00:00"))
                    || info.StationAddr.contains(QString("00:00:00:00:00:00"))
                    || info.StationAddr.contains(QString("FF:FF:FF:FF:FF:FF")))
                return;

            QTreeWidgetItem* subCurrentItem;
            listItem.clear();
            listItem = ui->ScannerTreeWidget->findItems(info.StationAddr, Qt::MatchExactly | Qt::MatchRecursive, SCANNER_COLUMN_BSSID);
            if(listItem.count() == 0)   // New station
            {
                subCurrentItem = new QTreeWidgetItem(currentItem);
                subCurrentItem->setText(SCANNER_COLUMN_SSID, "station");
                subCurrentItem->setText(SCANNER_COLUMN_BSSID, info.StationAddr);
                subCurrentItem->setText(SCANNER_COLUMN_DATAS, QString::number(1));
                currentItem->setText(SCANNER_COLUMN_STATIONS, QString::number(currentItem->childCount()));
            }
            else if(listItem.count() == 1)  // add data farme
            {
                subCurrentItem = listItem[0];
                int datas = subCurrentItem->text(SCANNER_COLUMN_DATAS).toInt();
                subCurrentItem->setText(SCANNER_COLUMN_DATAS, QString::number(++datas));
            }
            int totalDatas = currentItem->text(SCANNER_COLUMN_DATAS).toInt();
            currentItem->setText(SCANNER_COLUMN_DATAS, QString::number(++totalDatas));
        }
    }
}

void Widget::changeInfo()
{
#define MAX_CHANNEL 13
    ui->ChannelLabel->setText(QString("Channel : %1").arg(QString::number(((++currentChannel) % MAX_CHANNEL) + 1)));

    QString info = QString("iwconfig %1 channel %2").arg(QString(devName)).arg(QString::number((currentChannel % MAX_CHANNEL) + 1));
    system(info.toStdString().c_str());

    ui->StatuLabel->setText(QString("Running : %1pakets/s").arg(QString::number(packets)));
    packets = 0;
}

bool Widget::isMonitor()
{
    QProcess p;
    QString _iwconfig = QString("iwconfig %1").arg(QString(devName));
    p.start(_iwconfig.toStdString().c_str());
    p.waitForFinished(-1);

    QByteArray out = p.readAllStandardOutput();
    if(out.contains(QByteArray("Monitor")))
    {
        QString info = QString("iwconfig %1 channel %2").arg(QString(devName)).arg(QString::number(1));
        system(info.toStdString().c_str());
        return true;
    }
    return false;
}
