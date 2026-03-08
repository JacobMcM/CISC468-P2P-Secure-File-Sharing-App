#ifndef MDNS_H
#define MDNS_H

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#include <dns_sd.h>
#include <string>

// Need mDNS peer discovery functions for this file to be done.

#endif