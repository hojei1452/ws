#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTreeWidgetItem>
#include <QThread>
#include <QList>
#include <QDebug>
#include <QTimer>
#include <QProcess>
#include <QFileDialog>

#include "devicedialog.h"
#include "scanner.h"

enum scannerColumns
{
    SCANNER_COLUMN_SSID,
    SCANNER_COLUMN_BSSID,
    SCANNER_COLUMN_ENCRTPT,
    SCANNER_COLUMN_CHANNEL,
    SCANNER_COLUMN_SIGNAL,
    SCANNER_COLUMN_STATIONS,
    SCANNER_COLUMN_DATAS,
};

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

public slots:

private slots:
    void on_StartButton_clicked();
    void on_StopButton_clicked();
    void set_captureItem(ScannerInfo info);
    void changeInfo();
    void addPacket()    {   packets++;  }

private:
    Ui::Widget *ui;
    Scanner scanner;
    QThread scannerThread;

    QTimer timer;
    QThread timerThread;

    QString devName;

    int currentChannel;

    int packets;

protected:
    bool isMonitor();
};

#endif // WIDGET_H
