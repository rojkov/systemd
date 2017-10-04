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
