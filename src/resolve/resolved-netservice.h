#pragma once

#include "list.h"

typedef struct Netservice Netservice;

typedef struct Manager Manager;
typedef struct DnsResourceRecord DnsResourceRecord;

struct Netservice {
        char *filename;
        char *name;
        char *instance_name;
        char *type;
        uint16_t port;

        DnsResourceRecord *ptr_rr;
        DnsResourceRecord *srv_rr;
        DnsResourceRecord *txt_rr;

        LIST_FIELDS(Netservice, netservices);

        Manager *manager;
};

const struct ConfigPerfItem* resolved_netservice_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

void netservice_free(Netservice *netservice);

DEFINE_TRIVIAL_CLEANUP_FUNC(Netservice*, netservice_free);
#define _cleanup_netservice_free_ _cleanup_(netservice_freep)

int netservice_load(Manager *manager);
void netservice_remove_all(Netservice *first);
int netservice_update_rrs(Netservice *first, const char *hostname);
