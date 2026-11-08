/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Root qdiscs on veth pairs in a private network namespace: the rtnetlink
 * calls against the kernel, then netd's rules end to end. A veth pair made
 * with several tx queues stands in for a multi-queue device; every veth is
 * IFF_NO_QUEUE, so its root is noqueue with handle 0, which netd must leave
 * alone. The kernel's own mq default needs a device that is not
 * IFF_NO_QUEUE, which this test cannot make; the rule for it is covered by
 * test-netd-qdisc.
 *
 * Needs `ip`, `tc` and a kernel with veth, sch_fq_codel and sch_fq, and a private
 * user and network namespace (a fresh user namespace owns the net namespace
 * made with it, so CAP_NET_ADMIN is available without root). Without any of
 * these the test prints the reason and exits 77. It has no skip of its own for
 * cake: a kernel without it is the "failure is logged, not an error" case.
 *
 * net.core.default_qdisc exists only in the initial network namespace, so the
 * test sets Netd.default_qdisc itself where netd_startup() would have.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../test-util.h"
#include "netd-link.h"
#include "netd-network.h"
#include "netd-rtnl.h"
#include "netd.h"

#define SKIP_EXIT 77

static void skip(const char *reason) {
        fprintf(stderr, "test-netd-qdisc-link: skipped: %s\n", reason);
        exit(SKIP_EXIT);
}

static int sh(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static int sh(const char *fmt, ...) {
        char cmd[512];
        va_list ap;
        int len;

        va_start(ap, fmt);
        len = vsnprintf(cmd, sizeof(cmd), fmt, ap);
        va_end(ap);
        ASSERT_TRUE(len > 0 && (size_t) len < sizeof(cmd));

        return system(cmd);
}

static void write_proc_file(const char *path, const char *content) {
        FILE *f = fopen(path, "we");

        if (!f || fputs(content, f) < 0) {
                fprintf(stderr, "test-netd-qdisc-link: cannot write %s: %s\n", path, strerror(errno));
                skip("cannot map ids in a user namespace");
        }
        if (fclose(f) != 0)
                skip("cannot map ids in a user namespace");
}

static void enter_netns(void) {
        static bool in_userns;
        uid_t uid = getuid();
        gid_t gid = getgid();
        char buf[64];

        if (in_userns) {
                if (unshare(CLONE_NEWNET) < 0) {
                        fprintf(stderr, "unshare(CLONE_NEWNET): %s\n", strerror(errno));
                        skip("cannot create a network namespace");
                }
                return;
        }

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                fprintf(stderr, "unshare(CLONE_NEWUSER|CLONE_NEWNET): %s\n", strerror(errno));
                skip("cannot create a user and network namespace");
        }

        write_proc_file("/proc/self/setgroups", "deny");
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) uid);
        write_proc_file("/proc/self/uid_map", buf);
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) gid);
        write_proc_file("/proc/self/gid_map", buf);
        in_userns = true;
}

static void add_veth(const char *name, int queues) {
        if (sh("ip link add name %s numtxqueues %d numrxqueues %d type veth peer name %sp numtxqueues %d "
               "numrxqueues %d >/dev/null 2>&1",
               name,
               queues,
               queues,
               name,
               queues,
               queues) != 0)
                skip("cannot create a veth pair with `ip`");
}

/* The root qdisc as `ip link` reports it, independent of the code under test. */
static bool root_is(const char *ifname, const char *kind) {
        char cmd[256], line[1024];
        char want[64];
        FILE *p;
        bool found = false;

        snprintf(cmd, sizeof(cmd), "ip -o link show dev %s", ifname);
        snprintf(want, sizeof(want), " qdisc %s ", kind);

        p = popen(cmd, "r");
        ASSERT_TRUE(p != NULL);
        if (fgets(line, sizeof(line), p))
                found = strstr(line, want) != NULL;
        pclose(p);
        return found;
}

static void root_of(const char *ifname, char *kind, size_t len) {
        char cmd[256], line[1024];
        const char *q;
        FILE *p;

        snprintf(cmd, sizeof(cmd), "ip -o link show dev %s", ifname);
        p = popen(cmd, "r");
        ASSERT_TRUE(p != NULL);
        ASSERT_TRUE(fgets(line, sizeof(line), p) != NULL);
        pclose(p);

        q = strstr(line, " qdisc ");
        ASSERT_TRUE(q != NULL);
        q += strlen(" qdisc ");
        snprintf(kind, len, "%.*s", (int) strcspn(q, " "), q);
}

/* --- the rtnetlink calls --- */

typedef struct Seen {
        int ifindex;
        uint32_t tx;
} Seen;

static int collect(void *userdata, NetdRtnlLinkEvent event, const NetdRtnlLink *link) {
        Seen *seen = userdata;

        (void) event;
        if (strcmp(link->ifname, "qa0") == 0) {
                seen[0].ifindex = link->ifindex;
                seen[0].tx = link->num_tx_queues;
        } else if (strcmp(link->ifname, "qb0") == 0) {
                seen[1].ifindex = link->ifindex;
                seen[1].tx = link->num_tx_queues;
        }
        return 0;
}

static void test_rtnl_calls(void) {
        NetdRtnl *rtnl = NULL;
        Seen seen[2] = {
                { 0, 0 },
                { 0, 0 }
        };
        char kind[IFNAMSIZ], before[IFNAMSIZ];
        const char *first, *second;
        uint32_t handle = 77;
        int ifindex, r;

        enter_netns();
        add_veth("qa0", 4);
        add_veth("qb0", 1);

        ASSERT_EQ_INT(netd_rtnl_new(&rtnl), 0);
        netd_rtnl_set_link_handler(rtnl, collect, seen);
        ASSERT_TRUE(netd_rtnl_enumerate_links(rtnl) > 0);

        /* The tx queue count comes with the link. */
        ASSERT_TRUE(seen[0].ifindex > 0);
        ASSERT_EQ_INT(seen[0].tx, 4);
        ASSERT_EQ_INT(seen[1].tx, 1);
        ifindex = seen[0].ifindex;

        ASSERT_EQ_INT(netd_rtnl_link_up(rtnl, ifindex), 0);
        ASSERT_EQ_INT(netd_rtnl_qdisc_get_root(rtnl, ifindex, before, sizeof(before), &handle), 0);
        root_of("qa0", kind, sizeof(kind));
        ASSERT_STREQ(before, kind);

        /* The kernel's own root has handle 0. */
        ASSERT_EQ_INT(handle, 0);

        first = strcmp(before, "fq_codel") == 0 ? "fq" : "fq_codel";
        second = strcmp(first, "fq") == 0 ? "fq_codel" : "fq";

        r = netd_rtnl_qdisc_replace_root(rtnl, ifindex, first);
        if (r < 0) {
                fprintf(stderr, "replacing the root with %s: %s\n", first, strerror(-r));
                skip("the kernel has no fq_codel or fq qdisc");
        }
        ASSERT_TRUE(root_is("qa0", first));
        ASSERT_EQ_INT(netd_rtnl_qdisc_get_root(rtnl, ifindex, kind, sizeof(kind), &handle), 0);
        ASSERT_STREQ(kind, first);

        /* One made through RTM_NEWQDISC has a handle of its own. */
        ASSERT_TRUE(handle != 0);

        /* Replacing again with the other kind, and with the same kind. */
        ASSERT_EQ_INT(netd_rtnl_qdisc_replace_root(rtnl, ifindex, second), 0);
        ASSERT_TRUE(root_is("qa0", second));
        ASSERT_EQ_INT(netd_rtnl_qdisc_replace_root(rtnl, ifindex, second), 0);
        ASSERT_TRUE(root_is("qa0", second));

        /* A kind the kernel does not know is refused and changes nothing. */
        ASSERT_TRUE(netd_rtnl_qdisc_replace_root(rtnl, ifindex, "nosuchqdisc") < 0);
        ASSERT_TRUE(root_is("qa0", second));
        ASSERT_TRUE(netd_rtnl_qdisc_replace_root(rtnl, 99999, second) < 0);

        /* A delete naming another kind is refused. */
        ASSERT_TRUE(netd_rtnl_qdisc_delete_root(rtnl, ifindex, first) < 0);
        ASSERT_TRUE(root_is("qa0", second));

        /* The right kind gives the link the kernel's default back. */
        ASSERT_EQ_INT(netd_rtnl_qdisc_delete_root(rtnl, ifindex, second), 0);
        ASSERT_TRUE(!root_is("qa0", second));
        ASSERT_EQ_INT(netd_rtnl_qdisc_get_root(rtnl, ifindex, kind, sizeof(kind), &handle), 0);
        ASSERT_TRUE(strcmp(kind, second) != 0);
        ASSERT_EQ_INT(handle, 0);

        ASSERT_EQ_INT(netd_rtnl_qdisc_get_root(rtnl, 99999, kind, sizeof(kind), NULL) < 0, 1);

        netd_rtnl_free(rtnl);
        printf("test-netd-qdisc-link: rtnetlink calls ok\n");
}

/* --- netd end to end --- */

static void write_network(const char *dir, const char *name, const char *ifname, const char *extra) {
        char content[512];

        snprintf(content,
                 sizeof(content),
                 "[Match]\nName=%s\n\n[Network]\nAddress=10.253.%d.1/24\n\n%s",
                 ifname,
                 (int) (ifname[strlen(ifname) - 1] - '0'),
                 extra);
        ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
}

static void reload(Netd *n) {
        ASSERT_TRUE(n->reload_handler != NULL);
        ASSERT_EQ_INT(n->reload_handler(n), 0);
}

/* Runs link_configure() `times` times with stderr captured and returns the
 * number of lines the rtnetlink layer logged. */
static int count_rtnl_warnings(const char *dir, Link *l, int times) {
        char path[PATH_MAX];
        char line[1024];
        int saved, fd, i, count = 0;
        FILE *f;

        snprintf(path, sizeof(path), "%s/stderr-XXXXXX", dir);
        fd = mkstemp(path);
        ASSERT_TRUE(fd >= 0);
        fflush(stderr);
        saved = dup(STDERR_FILENO);
        ASSERT_TRUE(saved >= 0);
        ASSERT_TRUE(dup2(fd, STDERR_FILENO) >= 0);

        for (i = 0; i < times; i++)
                ASSERT_EQ_INT(link_configure(l), 0);

        fflush(stderr);
        ASSERT_TRUE(dup2(saved, STDERR_FILENO) >= 0);
        close(saved);

        f = fdopen(fd, "r");
        ASSERT_TRUE(f != NULL);
        rewind(f);
        while (fgets(line, sizeof(line), f))
                if (strstr(line, "netd: rtnl: kernel"))
                        count++;
        fclose(f);
        unlink(path);
        return count;
}

static void test_netd(void) {
        char *tmp;
        char netdir[PATH_MAX], rundir[PATH_MAX], statedir[PATH_MAX], resolv[PATH_MAX];
        const char *netpath[2];
        char kind[IFNAMSIZ], mq_before[IFNAMSIZ], single_before[IFNAMSIZ], unmanaged_before[IFNAMSIZ];
        Netd *n = NULL;
        NetdRtnl *rtnl = NULL;
        Link *mq, *sq, *gone, *ft, *tk;

        enter_netns();

        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);
        ASSERT_EQ_INT(test_mkdir(tmp, "network"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "run"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp, "state"), 0);
        snprintf(netdir, sizeof(netdir), "%s/network", tmp);
        snprintf(rundir, sizeof(rundir), "%s/run", tmp);
        snprintf(statedir, sizeof(statedir), "%s/state", tmp);
        snprintf(resolv, sizeof(resolv), "%s/resolv.conf", tmp);

        /* mq1: several queues, no section; sq2: one queue; mq3: several, a
         * section; um4: several, no .network; ft5: several, a root set with
         * tc before netd starts; tk6: several, a section. */
        add_veth("mq1", 4);
        add_veth("sq2", 1);
        add_veth("mq3", 4);
        add_veth("um4", 4);
        add_veth("ft5", 4);
        add_veth("tk6", 4);
        if (sh("tc qdisc replace dev ft5 root fq >/dev/null 2>&1") != 0)
                skip("the kernel has no fq qdisc");

        write_network(netdir, "10-mq1.network", "mq1", "");
        write_network(netdir, "20-sq2.network", "sq2", "");
        write_network(netdir, "30-mq3.network", "mq3", "[FairQueueingControlledDelay]\nParent=root\n");
        write_network(netdir, "50-ft5.network", "ft5", "[FairQueueingControlledDelay]\nParent=root\n");
        write_network(netdir, "60-tk6.network", "tk6", "[FairQueueing]\nParent=root\n");

        ASSERT_EQ_INT(netd_new(&n), 0);
        netpath[0] = netdir;
        netpath[1] = NULL;
        ASSERT_EQ_INT(netd_set_network_path(n, netpath), 0);
        ASSERT_EQ_INT(netd_set_runtime_dir(n, rundir), 0);
        ASSERT_EQ_INT(netd_set_state_dir(n, statedir), 0);
        ASSERT_EQ_INT(netd_set_resolv_conf(n, resolv), 0);
        snprintf(n->default_qdisc, sizeof(n->default_qdisc), "fq_codel");

        ASSERT_EQ_INT(netd_rtnl_new(&rtnl), 0);

        ASSERT_TRUE(root_is("ft5", "fq"));

        ASSERT_EQ_INT(netd_startup(n), 0);

        /* What the kernel gave the links, read through `ip` so netd's own
         * state cannot vouch for itself. A veth is IFF_NO_QUEUE, and the
         * kernel attaches that root when the link comes up. */
        root_of("mq1", mq_before, sizeof(mq_before));
        root_of("sq2", single_before, sizeof(single_before));
        root_of("um4", unmanaged_before, sizeof(unmanaged_before));
        ASSERT_STREQ(mq_before, "noqueue");

        /* The default of the multi-queue rule applies to an mq root only; a
         * multi-queue noqueue link keeps what the kernel gave it. */
        mq = netd_find_link_by_name(n, "mq1");
        sq = netd_find_link_by_name(n, "sq2");
        ASSERT_TRUE(mq != NULL && sq != NULL);
        ASSERT_EQ_INT(mq->num_tx_queues, 4);
        ASSERT_EQ_INT(sq->num_tx_queues, 1);
        ASSERT_EQ_INT(mq->state, LINK_CONFIGURED);
        ASSERT_TRUE(root_is("mq1", mq_before));
        ASSERT_STREQ(mq->qdisc, "");
        ASSERT_TRUE(root_is("sq2", single_before));
        ASSERT_STREQ(sq->qdisc, "");
        ASSERT_TRUE(root_is("um4", unmanaged_before));

        /* A section sets the kind on a link with several queues. */
        ASSERT_TRUE(root_is("mq3", "fq_codel"));
        ASSERT_STREQ(netd_find_link_by_name(n, "mq3")->qdisc, "fq_codel");
        ASSERT_TRUE(netd_find_link_by_name(n, "mq3")->qdisc_handle != 0);
        ASSERT_TRUE(root_is("tk6", "fq"));
        ASSERT_STREQ(netd_find_link_by_name(n, "tk6")->qdisc, "fq");

        /* A root put there by tc before netd started stays, whatever the file
         * names. */
        ft = netd_find_link_by_name(n, "ft5");
        ASSERT_TRUE(ft != NULL);
        ASSERT_TRUE(root_is("ft5", "fq"));
        ASSERT_STREQ(ft->qdisc, "");

        /* Nothing changes on a reload that changes nothing. */
        reload(n);
        ASSERT_TRUE(root_is("mq1", mq_before));
        ASSERT_TRUE(root_is("mq3", "fq_codel"));
        ASSERT_TRUE(root_is("ft5", "fq"));
        ASSERT_TRUE(root_is("sq2", single_before));

        /* An explicit kind applies to a link of any queue count and root. */
        write_network(netdir, "10-mq1.network", "mq1", "[FairQueueing]\nParent=root\n");
        write_network(netdir, "20-sq2.network", "sq2", "[FairQueueing]\nParent=root\n");
        reload(n);
        mq = netd_find_link_by_name(n, "mq1");
        sq = netd_find_link_by_name(n, "sq2");
        ASSERT_TRUE(root_is("mq1", "fq"));
        ASSERT_STREQ(mq->qdisc, "fq");
        ASSERT_TRUE(root_is("sq2", "fq"));
        ASSERT_STREQ(sq->qdisc, "fq");

        /* A root that something else set is left alone. */
        ASSERT_EQ_INT(netd_rtnl_qdisc_replace_root(rtnl, mq->ifindex, "mq"), 0);
        ASSERT_TRUE(root_is("mq1", "mq"));
        write_network(netdir, "10-mq1.network", "mq1", "[FairQueueingControlledDelay]\nParent=root\n");
        reload(n);
        mq = netd_find_link_by_name(n, "mq1");
        ASSERT_TRUE(root_is("mq1", "mq"));
        ASSERT_STREQ(mq->qdisc, "");
        ASSERT_EQ_INT(mq->state, LINK_CONFIGURED);

        /* The same kind installed over netd's own is not netd's: the handle
         * differs. */
        ASSERT_TRUE(root_is("tk6", "fq"));
        ASSERT_EQ_INT(sh("tc qdisc replace dev tk6 root handle 1: fq >/dev/null 2>&1"), 0);
        write_network(netdir, "60-tk6.network", "tk6", "[FairQueueingControlledDelay]\nParent=root\n");
        reload(n);
        tk = netd_find_link_by_name(n, "tk6");
        ASSERT_TRUE(root_is("tk6", "fq"));
        ASSERT_STREQ(tk->qdisc, "");

        /* A kind the kernel refuses is not an error and changes nothing. cake
         * is absent from many kernels; where it is present it is installed. */
        write_network(netdir, "20-sq2.network", "sq2", "[CAKE]\nParent=root\n");
        reload(n);
        sq = netd_find_link_by_name(n, "sq2");
        ASSERT_EQ_INT(sq->state, LINK_CONFIGURED);
        if (root_is("sq2", "cake"))
                ASSERT_STREQ(sq->qdisc, "cake");
        else {
                ASSERT_TRUE(root_is("sq2", "fq"));
                ASSERT_STREQ(sq->qdisc, "fq");
                ASSERT_STREQ(sq->qdisc_failed, "cake");

                /* Later events of the link do not send the refused kind again:
                 * the kernel's refusal is logged by the rtnetlink layer on
                 * every request. */
                ASSERT_EQ_INT(count_rtnl_warnings(tmp, sq, 3), 0);

                /* A reload clears the record, so the kind is sent and refused
                 * once more. */
                sq->qdisc_failed[0] = '\0';
                ASSERT_EQ_INT(count_rtnl_warnings(tmp, sq, 1), 1);
        }

        /* Dropping the section from a link removes what netd installed and
         * gives the kernel's choice back; a root netd does not own stays. */
        write_network(netdir, "20-sq2.network", "sq2", "");
        write_network(netdir, "50-ft5.network", "ft5", "");
        reload(n);
        sq = netd_find_link_by_name(n, "sq2");
        ASSERT_STREQ(sq->qdisc, "");
        root_of("sq2", kind, sizeof(kind));
        ASSERT_STREQ(kind, single_before);
        ASSERT_TRUE(root_is("ft5", "fq"));
        ASSERT_STREQ(netd_find_link_by_name(n, "ft5")->qdisc, "");

        /* A link that stops matching loses the qdisc netd gave it. */
        ASSERT_TRUE(root_is("mq3", "fq_codel"));
        write_network(netdir, "30-mq3.network", "nomatch", "");
        reload(n);
        gone = netd_find_link_by_name(n, "mq3");
        ASSERT_TRUE(gone != NULL);
        ASSERT_EQ_INT(gone->state, LINK_UNMANAGED);
        ASSERT_STREQ(gone->qdisc, "");
        ASSERT_TRUE(!root_is("mq3", "fq_codel"));

        netd_rtnl_free(rtnl);
        netd_free(n);
        test_rm_rf(tmp);
        free(tmp);
        printf("test-netd-qdisc-link: netd rules ok\n");
}

int main(void) {
        if (sh("command -v ip >/dev/null 2>&1") != 0)
                skip("`ip` is not installed");

        if (sh("command -v tc >/dev/null 2>&1") != 0)
                skip("`tc` is not installed");

        test_rtnl_calls();
        test_netd();

        printf("test-netd-qdisc-link: all checks passed\n");
        return 0;
}
