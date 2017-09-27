/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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
#include "dns-domain.h"
#include "list.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-zone.h"
#include "string-util.h"

/* Never allow more than 1K entries */
#define ZONE_MAX 1024

void dns_zone_item_probe_stop(DnsZoneItem *i) {
        DnsTransaction *t;
        assert(i);

        if (!i->probe_transaction)
                return;

        t = i->probe_transaction;
        i->probe_transaction = NULL;

        set_remove(t->notify_zone_items, i);
        set_remove(t->notify_zone_items_done, i);
        dns_transaction_gc(t);
}

static void dns_zone_item_free(DnsZoneItem *i) {
        if (!i)
                return;

        dns_zone_item_probe_stop(i);
        dns_resource_record_unref(i->rr);

        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsZoneItem*, dns_zone_item_free);

static void dns_zone_item_remove_and_free(DnsZone *z, DnsZoneItem *i) {
        DnsZoneItem *first;

        assert(z);

        if (!i)
                return;

        first = hashmap_get(z->by_key, i->rr->key);
        LIST_REMOVE(by_key, first, i);
        if (first)
                assert_se(hashmap_replace(z->by_key, first->rr->key, first) >= 0);
        else
                hashmap_remove(z->by_key, i->rr->key);

        first = hashmap_get(z->by_name, dns_resource_key_name(i->rr->key));
        LIST_REMOVE(by_name, first, i);
        if (first)
                assert_se(hashmap_replace(z->by_name, dns_resource_key_name(first->rr->key), first) >= 0);
        else
                hashmap_remove(z->by_name, dns_resource_key_name(i->rr->key));

        dns_zone_item_free(i);
}

void dns_zone_flush(DnsZone *z) {
        DnsZoneItem *i;

        assert(z);

        while ((i = hashmap_first(z->by_key)))
                dns_zone_item_remove_and_free(z, i);

        assert(hashmap_size(z->by_key) == 0);
        assert(hashmap_size(z->by_name) == 0);

        z->by_key = hashmap_free(z->by_key);
        z->by_name = hashmap_free(z->by_name);
}

static DnsZoneItem* dns_zone_get(DnsZone *z, DnsResourceRecord *rr) {
        DnsZoneItem *i;

        assert(z);
        assert(rr);

        LIST_FOREACH(by_key, i, hashmap_get(z->by_key, rr->key))
                if (dns_resource_record_equal(i->rr, rr) > 0)
                        return i;

        return NULL;
}

void dns_zone_remove_rr(DnsZone *z, DnsResourceRecord *rr) {
        DnsZoneItem *i;

        assert(z);
        assert(rr);

        i = dns_zone_get(z, rr);
        if (i)
                dns_zone_item_remove_and_free(z, i);
}

static int dns_zone_init(DnsZone *z) {
        int r;

        assert(z);

        r = hashmap_ensure_allocated(&z->by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&z->by_name, &dns_name_hash_ops);
        if (r < 0)
                return r;

        return 0;
}

static int dns_zone_link_item(DnsZone *z, DnsZoneItem *i) {
        DnsZoneItem *first;
        int r;

        first = hashmap_get(z->by_key, i->rr->key);
        if (first) {
                LIST_PREPEND(by_key, first, i);
                assert_se(hashmap_replace(z->by_key, first->rr->key, first) >= 0);
        } else {
                r = hashmap_put(z->by_key, i->rr->key, i);
                if (r < 0)
                        return r;
        }

        first = hashmap_get(z->by_name, dns_resource_key_name(i->rr->key));
        if (first) {
                LIST_PREPEND(by_name, first, i);
                assert_se(hashmap_replace(z->by_name, dns_resource_key_name(first->rr->key), first) >= 0);
        } else {
                r = hashmap_put(z->by_name, dns_resource_key_name(i->rr->key), i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_zone_item_probe_start(DnsZoneItem *i)  {
        DnsTransaction *t;
        int r;

        assert(i);

        if (i->probe_transaction)
                return 0;

        t = dns_scope_find_transaction(i->scope, &DNS_RESOURCE_KEY_CONST(i->rr->key->class, DNS_TYPE_ANY, dns_resource_key_name(i->rr->key)), false);
        if (!t) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(i->rr->key->class, DNS_TYPE_ANY, dns_resource_key_name(i->rr->key));
                if (!key)
                        return -ENOMEM;

                r = dns_transaction_new(&t, i->scope, key);
                if (r < 0)
                        return r;
        }

        r = set_ensure_allocated(&t->notify_zone_items, NULL);
        if (r < 0)
                goto gc;

        r = set_ensure_allocated(&t->notify_zone_items_done, NULL);
        if (r < 0)
                goto gc;

        r = set_put(t->notify_zone_items, i);
        if (r < 0)
                goto gc;

        i->probe_transaction = t;
        t->probing = true;

        if (t->state == DNS_TRANSACTION_NULL) {

                i->block_ready++;
                r = dns_transaction_go(t);
                i->block_ready--;

                if (r < 0) {
                        dns_zone_item_probe_stop(i);
                        return r;
                }
        }

        dns_zone_item_notify(i);
        return 0;

gc:
        dns_transaction_gc(t);
        return r;
}

int dns_zone_put(DnsZone *z, DnsScope *s, DnsResourceRecord *rr, bool probe) {
        _cleanup_(dns_zone_item_freep) DnsZoneItem *i = NULL;
        DnsZoneItem *existing;
        int r;

        assert(z);
        assert(s);
        assert(rr);

        if (dns_class_is_pseudo(rr->key->class))
                return -EINVAL;
        if (dns_type_is_pseudo(rr->key->type))
                return -EINVAL;

        existing = dns_zone_get(z, rr);
        if (existing)
                return 0;

        r = dns_zone_init(z);
        if (r < 0)
                return r;

        i = new0(DnsZoneItem, 1);
        if (!i)
                return -ENOMEM;

        i->scope = s;
        i->rr = dns_resource_record_ref(rr);
        i->probing_enabled = probe;

        r = dns_zone_link_item(z, i);
        if (r < 0)
                return r;

        if (probe) {
                DnsZoneItem *first, *j;
                bool established = false;

                /* Check if there's already an RR with the same name
                 * established. If so, it has been probed already, and
                 * we don't ned to probe again. */

                LIST_FIND_HEAD(by_name, i, first);
                LIST_FOREACH(by_name, j, first) {
                        if (i == j)
                                continue;

                        if (j->state == DNS_ZONE_ITEM_ESTABLISHED)
                                established = true;
                }

                if (established)
                        i->state = DNS_ZONE_ITEM_ESTABLISHED;
                else {
                        i->state = DNS_ZONE_ITEM_PROBING;

                        r = dns_zone_item_probe_start(i);
                        if (r < 0) {
                                dns_zone_item_remove_and_free(z, i);
                                i = NULL;
                                return r;
                        }
                }
        } else
                i->state = DNS_ZONE_ITEM_ESTABLISHED;

        i = NULL;
        return 0;
}

int dns_zone_lookup(DnsZone *z, DnsResourceKey *key, int ifindex, DnsAnswer **ret_answer, DnsAnswer **ret_soa, bool *ret_tentative) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        unsigned n_answer = 0;
        DnsZoneItem *j, *first;
        bool tentative = true, need_soa = false;
        int r;

        /* Note that we don't actually need the ifindex for anything. However when it is passed we'll initialize the
         * ifindex field in the answer with it */

        assert(z);
        assert(key);
        assert(ret_answer);

        /* First iteration, count what we have */

        log_debug("Lookup for %s", dns_resource_key_to_string(key, key_str, sizeof key_str));
        if (key->type == DNS_TYPE_ANY || key->class == DNS_CLASS_ANY) {
                bool found = false, added = false;
                int k;

                /* If this is a generic match, then we have to
                 * go through the list by the name and look
                 * for everything manually */

                first = hashmap_get(z->by_name, dns_resource_key_name(key));
                LIST_FOREACH(by_name, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;

                        k = dns_resource_key_match_rr(key, j->rr, NULL);
                        if (k < 0)
                                return k;
                        if (k > 0) {
                                n_answer++;
                                added = true;
                        }

                }

                if (found && !added)
                        need_soa = true;

        } else {
                bool found = false;

                /* If this is a specific match, then look for
                 * the right key immediately */

                first = hashmap_get(z->by_key, key);
                log_debug("*** first: %p", first);
                LIST_FOREACH(by_key, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING)) {
                                log_debug("Zone item is in %d - ignoring...", j->state);
                                continue;
                        }

                        found = true;
                        n_answer++;
                }

                if (!found) {
                        first = hashmap_get(z->by_name, dns_resource_key_name(key));
                        log_debug("*** first: %p", first);
                        LIST_FOREACH(by_name, j, first) {
                                if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING)) {
                                        log_debug("Zone item is in %d - ignoring...", j->state);
                                        continue;
                                }

                                need_soa = true;
                                break;
                        }
                }
        }

        if (n_answer <= 0 && !need_soa) {
                log_debug("No answers");
                goto return_empty;
        }

        if (n_answer > 0) {
                answer = dns_answer_new(n_answer);
                if (!answer)
                        return -ENOMEM;
        }

        if (need_soa) {
                soa = dns_answer_new(1);
                if (!soa)
                        return -ENOMEM;
        }

        /* Second iteration, actually add the RRs to the answers */
        if (key->type == DNS_TYPE_ANY || key->class == DNS_CLASS_ANY) {
                bool found = false, added = false;
                int k;

                first = hashmap_get(z->by_name, dns_resource_key_name(key));
                LIST_FOREACH(by_name, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;

                        if (j->state != DNS_ZONE_ITEM_PROBING)
                                tentative = false;

                        k = dns_resource_key_match_rr(key, j->rr, NULL);
                        if (k < 0)
                                return k;
                        if (k > 0) {
                                r = dns_answer_add(answer, j->rr, ifindex, DNS_ANSWER_AUTHENTICATED);
                                if (r < 0)
                                        return r;

                                added = true;
                        }
                }

                if (found && !added) {
                        r = dns_answer_add_soa(soa, dns_resource_key_name(key), LLMNR_DEFAULT_TTL, ifindex);
                        if (r < 0)
                                return r;
                }
        } else {
                bool found = false;

                first = hashmap_get(z->by_key, key);
                LIST_FOREACH(by_key, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;

                        if (j->state != DNS_ZONE_ITEM_PROBING)
                                tentative = false;

                        r = dns_answer_add(answer, j->rr, ifindex, DNS_ANSWER_AUTHENTICATED);
                        if (r < 0)
                                return r;
                }

                if (!found) {
                        log_debug("**");
                        bool add_soa = false;

                        first = hashmap_get(z->by_name, dns_resource_key_name(key));
                        LIST_FOREACH(by_name, j, first) {
                                if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                        continue;

                                if (j->state != DNS_ZONE_ITEM_PROBING)
                                        tentative = false;

                                add_soa = true;
                        }

                        if (add_soa) {
                                r = dns_answer_add_soa(soa, dns_resource_key_name(key), LLMNR_DEFAULT_TTL, ifindex);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        /* If the caller sets ret_tentative to NULL, then use this as
         * indication to not return tentative entries */

        if (!ret_tentative && tentative)
                goto return_empty;

        *ret_answer = answer;
        answer = NULL;

        if (ret_soa) {
                *ret_soa = soa;
                soa = NULL;
        }

        if (ret_tentative)
                *ret_tentative = tentative;

        return 1;

return_empty:
        log_debug("Nothing found");
        *ret_answer = NULL;

        if (ret_soa)
                *ret_soa = NULL;

        if (ret_tentative)
                *ret_tentative = false;

        return 0;
}

void dns_zone_item_conflict(DnsZoneItem *i) {
        assert(i);

        if (!IN_SET(i->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_VERIFYING, DNS_ZONE_ITEM_ESTABLISHED))
                return;

        log_info("Detected conflict on %s", strna(dns_resource_record_to_string(i->rr)));

        dns_zone_item_probe_stop(i);

        /* Withdraw the conflict item */
        i->state = DNS_ZONE_ITEM_WITHDRAWN;

        /* Maybe change the hostname */
        if (manager_is_own_hostname(i->scope->manager, dns_resource_key_name(i->rr->key)) > 0)
                manager_next_hostname(i->scope->manager);
}

void dns_zone_item_notify(DnsZoneItem *i) {
        assert(i);
        assert(i->probe_transaction);

        if (i->block_ready > 0)
                return;

        if (IN_SET(i->probe_transaction->state, DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_VALIDATING))
                return;

        if (i->probe_transaction->state == DNS_TRANSACTION_SUCCESS) {
                bool we_lost = false;

                /* The probe got a successful reply. If we so far
                 * weren't established we just give up. If we already
                 * were established, and the peer has the
                 * lexicographically larger IP address we continue
                 * and defend it. */

                if (!IN_SET(i->state, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING)) {
                        log_debug("Got a successful probe for not yet established RR, we lost.");
                        we_lost = true;
                } else {
                        assert(i->probe_transaction->received);
                        we_lost = (memcmp(&i->probe_transaction->received->sender, &i->probe_transaction->received->destination, FAMILY_ADDRESS_SIZE(i->probe_transaction->received->family)) < 0) && !(i->rr->key->type == DNS_TYPE_PTR && (dns_name_endswith(i->rr->ptr.name, "_tcp.local") || dns_name_endswith(i->rr->ptr.name, "_udp.local")));
                        if (we_lost)
                                log_debug("Got a successful probe reply for an established RR, and we have a lexicographically larger IP address and thus lost.");
                }

                if (we_lost) {
                        dns_zone_item_conflict(i);
                        return;
                }

                log_debug("Got a successful probe reply, but peer has lexicographically lower IP address and thus lost.");
        }

        log_debug("Record %s successfully probed.", strna(dns_resource_record_to_string(i->rr)));

        dns_zone_item_probe_stop(i);
        i->state = DNS_ZONE_ITEM_ESTABLISHED;
}

static int dns_zone_item_verify(DnsZoneItem *i) {
        int r;

        assert(i);

        if (i->state != DNS_ZONE_ITEM_ESTABLISHED)
                return 0;

        log_debug("Verifying RR %s", strna(dns_resource_record_to_string(i->rr)));

        i->state = DNS_ZONE_ITEM_VERIFYING;
        r = dns_zone_item_probe_start(i);
        if (r < 0) {
                log_error_errno(r, "Failed to start probing for verifying RR: %m");
                i->state = DNS_ZONE_ITEM_ESTABLISHED;
                return r;
        }

        return 0;
}

int dns_zone_check_conflicts(DnsZone *zone, DnsResourceRecord *rr) {
        DnsZoneItem *i, *first;
        int c = 0;

        assert(zone);
        assert(rr);

        /* This checks whether a response RR we received from somebody
         * else is one that we actually thought was uniquely ours. If
         * so, we'll verify our RRs. */

        /* No conflict if we don't have the name at all. */
        first = hashmap_get(zone->by_name, dns_resource_key_name(rr->key));
        if (!first)
                return 0;

        /* No conflict if we have the exact same RR */
        if (dns_zone_get(zone, rr))
                return 0;

        /* OK, somebody else has RRs for the same name. Yuck! Let's
         * start probing again */

        LIST_FOREACH(by_name, i, first) {
                if (dns_resource_record_equal(i->rr, rr))
                        continue;

                dns_zone_item_verify(i);
                c++;
        }

        return c;
}

int dns_zone_verify_conflicts(DnsZone *zone, DnsResourceKey *key) {
        DnsZoneItem *i, *first;
        int c = 0;

        assert(zone);

        /* Somebody else notified us about a possible conflict. Let's
         * verify if that's true. */

        first = hashmap_get(zone->by_name, dns_resource_key_name(key));
        if (!first)
                return 0;

        LIST_FOREACH(by_name, i, first) {
                dns_zone_item_verify(i);
                c++;
        }

        return c;
}

void dns_zone_verify_all(DnsZone *zone) {
        DnsZoneItem *i;
        Iterator iterator;

        assert(zone);

        HASHMAP_FOREACH(i, zone->by_key, iterator) {
                DnsZoneItem *j;

                LIST_FOREACH(by_key, j, i)
                        dns_zone_item_verify(j);
        }
}

void dns_zone_dump(DnsZone *zone, FILE *f) {
        Iterator iterator;
        DnsZoneItem *i;

        if (!zone)
                return;

        if (!f)
                f = stdout;

        HASHMAP_FOREACH(i, zone->by_key, iterator) {
                DnsZoneItem *j;

                LIST_FOREACH(by_key, j, i) {
                        const char *t;

                        t = dns_resource_record_to_string(j->rr);
                        if (!t) {
                                log_oom();
                                continue;
                        }

                        fputc('\t', f);
                        fputs(t, f);
                        fputc('\n', f);
                }
        }
}

bool dns_zone_is_empty(DnsZone *zone) {
        if (!zone)
                return true;

        return hashmap_isempty(zone->by_key);
}
