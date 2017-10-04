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

#include "conf-files.h"
#include "conf-parser.h"
#include "hexdecoct.h"
#include "resolved-dnssd.h"
#include "resolved-dns-rr.h"
#include "resolved-manager.h"
#include "strv.h"

#define BASE64_PREFIX "base64:"

const char* const dnssd_service_dirs[] = {
        "/etc/systemd/dnssd",
        "/run/systemd/dnssd",
        "/usr/lib/systemd/dnssd",
#ifdef HAVE_SPLIT_USR
        "/lib/systemd/dnssd",
#endif
    NULL
};

DnssdService *dnssd_service_free(DnssdService *service) {
        if (!service)
                return NULL;

        if (service->manager)
                hashmap_remove(service->manager->dnssd_services, service->name);

        dns_resource_record_unref(service->ptr_rr);
        dns_resource_record_unref(service->srv_rr);
        dns_resource_record_unref(service->txt_rr);

        free(service->filename);
        free(service->name);
        free(service->type);
        free(service->instance_name);
        dns_txt_item_free_all(service->txt);

        return mfree(service);
}

static int dnssd_service_load(Manager *manager, const char *filename) {
        _cleanup_(dnssd_service_freep) DnssdService *service = NULL;
        char *d;
        const char *dropin_dirname;
        int r;

        assert(manager);
        assert(filename);

        service = new0(DnssdService, 1);
        if (!service)
                return log_oom();

        service->manager = manager;

        service->filename = strdup(filename);
        if (!service->filename)
                return log_oom();

        service->name = strdup(basename(filename));
        if (!service->name)
                return log_oom();

        d = endswith(service->name, ".dnssd");
        if (!d)
                return -EINVAL;

        assert(streq(d, ".dnssd"));

        *d = '\0';

        dropin_dirname = strjoina(service->name, ".dnssd.d");

        r = config_parse_many(filename, dnssd_service_dirs, dropin_dirname,
                              "Service\0",
                              config_item_perf_lookup, resolved_dnssd_gperf_lookup,
                              false, service);
        if (r < 0)
                return r;

        if (!service->instance_name) {
                log_error("%s doesn't define service instance name", service->name);
                return -EINVAL;
        }

        if (!service->type) {
                log_error("%s doesn't define service type", service->name);
                return -EINVAL;
        }

        r = hashmap_ensure_allocated(&manager->dnssd_services, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(manager->dnssd_services, service->name, service);
        if (r < 0)
                return r;

        service = NULL;

        return 0;
}

int dnssd_load(Manager *manager) {
        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(manager);

        r = conf_files_list_strv(&files, ".dnssd", NULL, 0, dnssd_service_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .dnssd files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = dnssd_service_load(manager, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dnssd_txt_item_new(const char *key, const char *value, DnsTxtItem **ret_item) {
        _cleanup_free_ void *unescaped = NULL;
        size_t sz, length = 0;
        DnsTxtItem *i;
        int r;

        sz = strlen(key);

        if (value) {
                if (startswith(value, BASE64_PREFIX)) {
                        r = unbase64mem(value + strlen(BASE64_PREFIX),
                                        strlen(value) - strlen(BASE64_PREFIX), &unescaped, &length);
                        if (r < 0)
                                return r;
                } else {
                        length = strlen(value);
                        unescaped = strdup(value);
                }

                sz += length + 1; /* value plus '=' */
        }

        i = malloc0(offsetof(DnsTxtItem, data) + sz + 1); /* for safety reasons we add an extra NUL byte */
        if (!i)
                return -ENOMEM;

        memcpy(i->data, key, strlen(key));
        if (length > 0) {
                memcpy(i->data + strlen(key), "=", 1);
                memcpy(i->data + strlen(key) + 1, unescaped, length);
        }
        i->length = sz;

        *ret_item = i;
        i = NULL;

        return 0;
}
