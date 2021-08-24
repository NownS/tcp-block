TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap -lnet
SOURCES += \
    ip.cpp \
    mac.cpp \
    main.cpp \
    strnstr.cpp

HEADERS += \
    ip.h \
    mac.h \
    strnstr.h
