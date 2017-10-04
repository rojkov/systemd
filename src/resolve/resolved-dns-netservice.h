#pragma once

#include "list.h"

typedef struct DnsNetservice DnsNetservice;

typedef struct Manager Manager;
typedef struct DnsResourceRecord DnsResourceRecord;

struct DnsNetservice {
        char *filename;
        char *name;
        char *instance_name;
        char *type;
        uint16_t port;
        uint16_t priority;
        uint16_t weight;
        char **txt;

        DnsResourceRecord *ptr_rr;
        DnsResourceRecord *srv_rr;
        DnsResourceRecord *txt_rr;

        LIST_FIELDS(DnsNetservice, netservices);

        Manager *manager;
};

int dns_netservice_load(Manager *manager);
void dns_netservice_remove_all(DnsNetservice *first);
int dns_netservice_update_rrs(DnsNetservice *first, const char *hostname);
