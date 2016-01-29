#-------------------------------------------------
#
# Project created by QtCreator 2016-01-22T06:29:38
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = WirelessSniffer
TEMPLATE = app


LIBS += -lpcap


SOURCES += main.cpp\
        widget.cpp \
    devicedialog.cpp \
    scanner.cpp

HEADERS  += widget.h \
    devicedialog.h \
    ieee80211_radiotap.h \
    scanner.h

FORMS    += widget.ui \
    devicedialog.ui

DISTFILES +=
