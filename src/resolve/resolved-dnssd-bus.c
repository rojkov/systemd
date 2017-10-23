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

#include "alloc-util.h"
#include "resolved-dnssd-bus.h"
#include "resolved-link.h"
#include "strv.h"

int bus_dnssd_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        DnssdService *s = userdata;
        Manager *m;
        Iterator i;
        Link *l;
        int r;

        assert(message);
        assert(s);

        m = s->manager;

        HASHMAP_FOREACH(l, m->links, i) {
                if (l->mdns_ipv4_scope) {
                        r = dns_scope_announce(l->mdns_ipv4_scope, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to send goodbye messages in IPv4 scope: %m");

                        dns_zone_remove_rr(&l->mdns_ipv4_scope->zone, s->ptr_rr);
                        dns_zone_remove_rr(&l->mdns_ipv4_scope->zone, s->srv_rr);
                        dns_zone_remove_rr(&l->mdns_ipv4_scope->zone, s->txt_rr);
                }

                if (l->mdns_ipv6_scope) {
                        r = dns_scope_announce(l->mdns_ipv6_scope, true);
                        if (r < 0)
                                log_warning_errno(r, "Failed to send goodbye messages in IPv6 scope: %m");

                        dns_zone_remove_rr(&l->mdns_ipv6_scope->zone, s->ptr_rr);
                        dns_zone_remove_rr(&l->mdns_ipv6_scope->zone, s->srv_rr);
                        dns_zone_remove_rr(&l->mdns_ipv6_scope->zone, s->txt_rr);
                }
        }

        dnssd_service_free(s);

        manager_refresh_rrs(m);

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable dnssd_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("Unregister", NULL, NULL, bus_dnssd_method_unregister, 0),
        SD_BUS_SIGNAL("Conflicted", "o", 0),

        SD_BUS_VTABLE_END
};

int dnssd_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        Manager *m = userdata;
        DnssdService *service;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = sd_bus_path_decode(path, "/org/freedesktop/resolve1/dnssd", &name);
        if (r <= 0)
                return 0;

        service = hashmap_get(m->dnssd_services, name);
        if (!service)
                return 0;

        *found = service;
        return 1;
}

int dnssd_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        DnssdService *service;
        Iterator i;
        unsigned c = 0;
        int r;

        assert(bus);
        assert(path);
        assert(m);
        assert(nodes);

        l = new0(char*, hashmap_size(m->dnssd_services) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(service, m->dnssd_services, i) {
                char *p;

                r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", service->name, &p);
                if (r < 0)
                        return r;

                l[c++] = p;
        }

        l[c] = NULL;
        *nodes = l;
        l = NULL;

        return 1;
}
