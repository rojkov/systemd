#include "conf-files.h"
#include "conf-parser.h"
#include "list.h"
#include "resolved-dns-netservice.h"
#include "resolved-dns-rr.h"
#include "resolved-manager.h"
#include "strv.h"

const char* const netservice_dirs[] = {
    "/etc/systemd/resolve",
    NULL
};

static void dns_netservice_free(DnsNetservice *netservice) {
    if (!netservice)
        return;

    assert(netservice->manager->n_netservices > 0);
    LIST_REMOVE(netservices, netservice->manager->netservices, netservice);
    netservice->manager->n_netservices--;

    dns_resource_record_unref(netservice->ptr_rr);
    dns_resource_record_unref(netservice->srv_rr);
    dns_resource_record_unref(netservice->txt_rr);

    free(netservice->filename);
    free(netservice->name);
    free(netservice->type);
    free(netservice->instance_name);
    strv_free(netservice->txt);

    free(netservice);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsNetservice*, dns_netservice_free);

static int dns_netservice_load_one(Manager *manager, const char *filename) {
    _cleanup_(dns_netservice_freep) DnsNetservice *netservice = NULL;
    const char *dropin_dirname;
    int r;

    assert(manager);
    assert(filename);

    netservice = new0(DnsNetservice, 1);
    if (!netservice)
        return log_oom();

    netservice->manager = manager;

    LIST_PREPEND(netservices, manager->netservices, netservice);
    manager->n_netservices++;

    netservice->filename = strdup(filename);
    if (!netservice->filename)
        return log_oom();

    netservice->name = strdup(basename(filename));
    if (!netservice->name)
        return log_oom();

    dropin_dirname = strjoina(netservice->name, ".netservice.d");

    r = config_parse_many(filename, netservice_dirs, dropin_dirname,
            "Service\0",
            config_item_perf_lookup, resolved_netservice_gperf_lookup,
            false, netservice);
    if (r < 0)
        return r;

    if (!netservice->instance_name) {
            log_error("%s doesn't define service instance name", netservice->name);
            return -EINVAL;
    }

    if (!netservice->type) {
            log_error("%s doesn't define service type", netservice->name);
            return -EINVAL;
    }

    if (!set_contains(manager->netservice_types, netservice->type)) {
        r = set_ensure_allocated(&manager->netservice_types, &string_hash_ops);
        if (r < 0)
            return r;

        r = set_put_strdup(manager->netservice_types, netservice->type);
        if (r < 0)
            return r;
    }

    netservice = NULL;

    return 0;
}

int dns_netservice_load(Manager *manager) {
    _cleanup_strv_free_ char **files = NULL;
    char **f;
    int r;

    assert(manager);

    r = conf_files_list_strv(&files, ".netservice", NULL, netservice_dirs);
    if (r < 0)
        return log_error_errno(r, "Failed to enumerate netservice files: %m");

    STRV_FOREACH_BACKWARDS(f, files) {
        r = dns_netservice_load_one(manager, *f);
        if (r < 0)
            return r;
    }

    return 0;
}

void dns_netservice_remove_all(DnsNetservice *first) {
    DnsNetservice *next;

    if (!first)
        return;

    next = first->netservices_next;
    dns_netservice_free(first);

    dns_netservice_remove_all(next);
}

int dns_netservice_update_rrs(DnsNetservice *first, const char *hostname) {
        char *service_name;
        char *instance_name;
        DnsNetservice *next;

        if (!first)
                return 0;

        next = first->netservices_next;

        if (first->ptr_rr)
                first->ptr_rr = dns_resource_record_unref(first->ptr_rr);
        if (first->srv_rr)
                first->srv_rr = dns_resource_record_unref(first->srv_rr);
        if (first->txt_rr)
                first->txt_rr = dns_resource_record_unref(first->txt_rr);

        service_name = strjoina(first->type, ".local");
        instance_name = strjoina(first->instance_name, ".", first->type, ".local");

        first->txt_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT,
                                                     instance_name);
        if (!first->txt_rr)
                goto oom;

        if (strv_length(first->txt) > 0) {
                DnsTxtItem *last = NULL;
                char **value;

                STRV_FOREACH(value, first->txt) {
                        DnsTxtItem *i;
                        size_t sz;

                        sz = strlen(*value);
                        i = malloc0(offsetof(DnsTxtItem, data) + sz + 1);
                        if (!i)
                                goto oom;

                        memcpy(i->data, *value, sz);
                        i->length = sz;

                        LIST_INSERT_AFTER(items, first->txt_rr->txt.items, last, i);
                        last = i;
                }
        } else {
                DnsTxtItem *i;

                /* RFC 6763, section 6.1 suggests to treat
                 * empty TXT RRs as equivalent to a TXT record
                 * with a single empty string. */

                i = malloc0(offsetof(DnsTxtItem, data) + 1); /* for safety reasons we add an extra NUL byte */
                if (!i)
                        goto oom;

                first->txt_rr->txt.items = i;
        }
        first->txt_rr->ttl = MDNS_DEFAULT_TTL;

        first->ptr_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR,
                                                     service_name);
        if (!first->ptr_rr)
                goto oom;

        first->ptr_rr->ttl = MDNS_DEFAULT_TTL;
        first->ptr_rr->ptr.name = strdup(instance_name);
        if (!first->ptr_rr->ptr.name)
                goto oom;

        first->srv_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV,
                                                     instance_name);
        if (!first->srv_rr)
                goto oom;

        first->srv_rr->ttl = MDNS_DEFAULT_TTL;
        first->srv_rr->srv.priority = first->priority;
        first->srv_rr->srv.weight = first->weight;
        first->srv_rr->srv.port = first->port;
        first->srv_rr->srv.name = strdup(hostname);
        if (!first->srv_rr->srv.name)
                goto oom;

        return dns_netservice_update_rrs(next, hostname);

oom:
        if (first->txt_rr)
                first->txt_rr = dns_resource_record_unref(first->txt_rr);
        if (first->ptr_rr)
                first->ptr_rr = dns_resource_record_unref(first->ptr_rr);
        if (first->srv_rr)
                first->srv_rr = dns_resource_record_unref(first->srv_rr);
        return log_oom();
}
