#include "conf-files.h"
#include "conf-parser.h"
#include "resolved-netservice.h"
#include "resolved-manager.h"
#include "resolved-dns-rr.h"
#include "strv.h"

void netservice_free(Netservice *netservice) {
    if (!netservice)
        return;

    dns_resource_record_unref(netservice->ptr_rr);
    dns_resource_record_unref(netservice->srv_rr);
    dns_resource_record_unref(netservice->txt_rr);

    free(netservice->filename);
    free(netservice->name);
    free(netservice->type);
    free(netservice->instance_name);

    free(netservice);
}

const char* const netservice_dirs[] = {
    "/etc/systemd/resolve",
    NULL
};


static int netservice_load_one(Manager *manager, const char *filename) {
    _cleanup_netservice_free_ Netservice *netservice = NULL;
    const char *dropin_dirname;
    int r;

    assert(manager);
    assert(filename);

    netservice = new0(Netservice, 1);
    if (!netservice)
        return log_oom();

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

    if (!set_contains(manager->netservice_types, netservice->type)) {
        r = set_ensure_allocated(&manager->netservice_types, &string_hash_ops);
        if (r < 0)
            return r;

        r = set_put_strdup(manager->netservice_types, netservice->type);
        if (r < 0)
            return r;
    }

    LIST_PREPEND(netservices, manager->netservices, netservice);

    netservice = NULL;

    return 0;
}

int netservice_load(Manager *manager) {
    _cleanup_strv_free_ char **files = NULL;
    char **f;
    int r;

    assert(manager);

    r = conf_files_list_strv(&files, ".netservice", NULL, netservice_dirs);
    if (r < 0)
        return log_error_errno(r, "Failed to enumerate netservice files: %m");

    STRV_FOREACH_BACKWARDS(f, files) {
        r = netservice_load_one(manager, *f);
        if (r < 0)
            return r;
    }

    return 0;
}

void netservice_remove_all(Netservice *first) {
    Netservice *next;

    if (!first)
        return;

    next = first->netservices_next;
    netservice_free(first);

    netservice_remove_all(next);
}

int netservice_update_rrs(Netservice *first, const char *hostname) {
        char *service_name;
        char *instance_name;
        Netservice *next;
        DnsTxtItem *i;

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
                return log_oom();

        /* RFC 6763, section 6.1 suggests to treat
         * empty TXT RRs as equivalent to a TXT record
         * with a single empty string. */

        i = malloc0(offsetof(DnsTxtItem, data) + 1); /* for safety reasons we add an extra NUL byte */
        if (!i) {
                first->txt_rr = dns_resource_record_unref(first->txt_rr);
                return log_oom();
        }

        first->txt_rr->txt.items = i;
        first->txt_rr->ttl = MDNS_DEFAULT_TTL;

        first->ptr_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR,
                                                     service_name);
        if (!first->ptr_rr) {
                first->txt_rr = dns_resource_record_unref(first->txt_rr);
                return log_oom();
        }

        first->ptr_rr->ttl = MDNS_DEFAULT_TTL;
        first->ptr_rr->ptr.name = strdup(instance_name);

        first->srv_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV,
                                                     instance_name);
        if (!first->srv_rr) {
                first->txt_rr = dns_resource_record_unref(first->txt_rr);
                first->ptr_rr = dns_resource_record_unref(first->ptr_rr);
                return log_oom();
        }

        first->srv_rr->ttl = MDNS_DEFAULT_TTL;
        first->srv_rr->srv.priority = 0; /* TODO: add priority to config */
        first->srv_rr->srv.weight = 0; /* TODO: add weight to config */
        first->srv_rr->srv.port = first->port;
        first->srv_rr->srv.name = strdup(hostname);

        return netservice_update_rrs(next, hostname);
}
