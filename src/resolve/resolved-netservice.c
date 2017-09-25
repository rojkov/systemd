#include "conf-files.h"
#include "conf-parser.h"
#include "resolved-netservice.h"
#include "resolved-manager.h"
#include "strv.h"

void netservice_free(Netservice *netservice) {
    if (!netservice)
        return;

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

    r = conf_files_list_strv(&files, ".netservice", NULL, 0, netservice_dirs);
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
