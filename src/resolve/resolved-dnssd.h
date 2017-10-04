#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Dmitry Rozhkov

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct DnssdService DnssdService;

typedef struct Manager Manager;
typedef struct DnsResourceRecord DnsResourceRecord;
typedef struct DnsTxtItem DnsTxtItem;

struct DnssdService {
        char *filename;
        char *name;
        char *instance_name;
        char *type;
        uint16_t port;
        uint16_t priority;
        uint16_t weight;
        DnsTxtItem *txt;

        DnsResourceRecord *ptr_rr;
        DnsResourceRecord *srv_rr;
        DnsResourceRecord *txt_rr;

        Manager *manager;
};

DnssdService *dnssd_service_free(DnssdService *service);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdService*, dnssd_service_free);

int dnssd_load(Manager *manager);
int dnssd_txt_item_new(const char *key, const char *value, DnsTxtItem **ret_item);