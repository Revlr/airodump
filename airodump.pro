TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap -pthread

SOURCES += main.cpp \
    pkt.cpp

HEADERS += \
    pkt.h
