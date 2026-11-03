/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netctl's options, verbs and exit statuses, checked against networkctl v262:
 * the real built `netctl` binary runs as a subprocess (test-netctl-color.c's
 * pattern) because the verbs are file-local statics. The fixture is "lo",
 * which every namespace has; nothing here depends on its state.
 */

#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../test-util.h"

#define RUNTIME_DIR "/run/systemd/network"
#define LLDP_DIR "/run/netd/lldp"
/* Files are named after an ifindex: lo's for the fixture, ones no link has for the rest. */
#define LLDP_OTHER LLDP_DIR "/999999"
#define LLDP_STALE LLDP_DIR "/999998"
static char lldp_fixture[64];
#define FIXTURE "picotest-netctl-opts.network"

#define STARTS(s, lit) (strncmp((s), (lit), sizeof(lit) - 1) == 0)

static char netctl_path[PATH_MAX];

struct run_result {
        char out[16384];
        int exit_code;
};

static int sibling_binary_path(const char *name, char *out, size_t out_size) {
        char self[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        char *slash;

        if (n < 0)
                return -errno;
        self[n] = '\0';
        slash = strrchr(self, '/');
        if (!slash)
                return -ENOENT;
        *slash = '\0';
        n = snprintf(out, out_size, "%s/%s", self, name);
        return n < 0 || (size_t) n >= out_size ? -ENAMETOOLONG : 0;
}

/* netctl with the NULL-terminated argument list, stdout captured. */
static void run(struct run_result *res, ...) {
        char *args[16] = { netctl_path };
        int n = 1, pipefd[2], status;
        size_t total = 0;
        va_list ap;
        pid_t pid;
        const char *a;

        va_start(ap, res);
        while (n < 15 && (a = va_arg(ap, const char *)) != NULL)
                args[n++] = (char *) a;
        va_end(ap);
        args[n] = NULL;

        res->out[0] = '\0';
        res->exit_code = -1;
        ASSERT_EQ_INT(pipe(pipefd), 0);
        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
                execv(netctl_path, args);
                _exit(127);
        }
        close(pipefd[1]);
        for (;;) {
                char buf[1024];
                ssize_t r = read(pipefd[0], buf, sizeof buf);

                if (r <= 0)
                        break;
                if (total + (size_t) r < sizeof res->out - 1) {
                        memcpy(res->out + total, buf, (size_t) r);
                        total += (size_t) r;
                }
        }
        res->out[total] = '\0';
        close(pipefd[0]);
        ASSERT_TRUE(waitpid(pid, &status, 0) >= 0);
        res->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_accepted_options(void) {
        struct run_result plain, r;
        static const char * const accepted[][2] = {
                {        "--no-pager", NULL },
                { "--no-ask-password", NULL },
                {                "-l", NULL },
                {            "--full", NULL },
                {                "-n",  "5" },
                {         "--lines=7", NULL },
                {       "--no-reload", NULL },
                {         "--runtime", NULL },
                {           "--stdin", NULL },
                {       "--drop-in=x", NULL },
        };

        run(&plain, "list", "lo", NULL);
        ASSERT_EQ_INT(plain.exit_code, 0);

        /* Stubs change nothing about the output. */
        for (size_t i = 0; i < sizeof accepted / sizeof accepted[0]; i++) {
                if (accepted[i][1])
                        run(&r, accepted[i][0], accepted[i][1], "list", "lo", NULL);
                else
                        run(&r, accepted[i][0], "list", "lo", NULL);
                ASSERT_EQ_INT(r.exit_code, 0);
                ASSERT_STREQ(r.out, plain.out);
        }

        run(&r, "--lines=x", "list", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "--drop-in=", "list", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "--no-such-option", "list", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
}

static void test_help_version(void) {
        struct run_result r;

        run(&r, "--help", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "Usage: networkctl") != NULL);
        ASSERT_TRUE(strstr(r.out, "--no-legend") != NULL);

        run(&r, "-h", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);

        run(&r, "--version", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(r.out, "networkctl "));
}

static void test_list(void) {
        struct run_result r;

        run(&r, "list", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(r.out, "IDX LINK TYPE"));
        ASSERT_TRUE(strstr(r.out, "\n  1 lo   loopback ") != NULL);
        ASSERT_TRUE(strstr(r.out, "\n1 links listed.\n") != NULL);

        /* Index, glob and index-glob patterns reach the same link. */
        run(&r, "list", "1", NULL);
        ASSERT_TRUE(strstr(r.out, " lo ") != NULL);
        run(&r, "list", "l*", NULL);
        ASSERT_TRUE(strstr(r.out, " lo ") != NULL);

        run(&r, "--no-legend", "list", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "IDX") == NULL);
        ASSERT_TRUE(strstr(r.out, "links listed") == NULL);
        ASSERT_TRUE(strstr(r.out, " lo ") != NULL);

        /* A glob may match nothing, a plain name may not. */
        run(&r, "list", "picotest-nomatch*", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "\n0 links listed.\n") != NULL);
        run(&r, "list", "picotest-nolink", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        ASSERT_STREQ(r.out, "");
}

static void test_json(void) {
        struct run_result r, plain, off;

        run(&r, "--json=short", "list", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(r.out, "{\"Index\":1,\"Name\":\"lo\","));
        ASSERT_TRUE(strstr(r.out, "\"Type\":\"loopback\"") != NULL);
        ASSERT_TRUE(strchr(r.out, '\n') == r.out + strlen(r.out) - 1);

        run(&r, "--json=pretty", "list", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(r.out, "{\n  \"Index\" : 1,\n  \"Name\" : \"lo\",\n"));
        ASSERT_TRUE(strstr(r.out, "\n}\n") != NULL);

        /* No pattern, or --all: the whole manager in an Interfaces array. */
        run(&r, "--json=short", "status", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(r.out, "{\"Interfaces\":[{\"Index\":1,"));
        run(&r, "--json=short", "-a", "list", "lo", NULL);
        ASSERT_TRUE(STARTS(r.out, "{\"Interfaces\":["));

        run(&plain, "list", NULL);
        run(&off, "--json=off", "list", NULL);
        ASSERT_STREQ(off.out, plain.out);

        run(&r, "--json=help", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_STREQ(r.out, "pretty\nshort\noff\n");
        run(&r, "--json=bogus", "list", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);

        run(&r, "--json=short", "lldp", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(r.out, "{\"Neighbors\":["));
}

static void test_status(void) {
        struct run_result r;
        bool multiple;

        run(&r, "status", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "Rx Packets") == NULL);

        run(&r, "status", "-s", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "Rx Packets:") != NULL);
        ASSERT_TRUE(strstr(r.out, "Collisions:") != NULL);

        run(&r, "status", "picotest-nolink", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        ASSERT_STREQ(r.out, "");

        /* --all shows every link, blocks separated by a blank line. */
        run(&r, "list", "--no-legend", NULL);
        multiple = strchr(r.out, '\n') != strrchr(r.out, '\n') && strstr(r.out, "links listed") == NULL;
        run(&r, "status", "-a", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "\xe2\x97\x8f 1: lo\n") != NULL);
        ASSERT_TRUE(!multiple || strstr(r.out, "\n\n") != NULL);
}

static void test_lldp(void) {
        struct run_result r;

        run(&r, "lldp", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(STARTS(
                        r.out,
                        "LINK SYSTEM-NAME SYSTEM-DESCRIPTION CHASSIS-ID PORT-ID PORT-DESCRIPTION CAPS\n"));

        run(&r, "--no-legend", "lldp", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_STREQ(r.out, "");
}

static void write_file(const char *path, const char *content) {
        FILE *f = fopen(path, "we");

        ASSERT_TRUE(f != NULL);
        fputs(content, f);
        fclose(f);
}

/* The neighbours of one link in the file netd would write; "lo" is the only link every namespace has. */
#define LLDP_ONE      \
        "IFNAME=lo\n" \
        "N chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1 name=sw-1 sysdescr=Switch%20OS descr=uplink enabled=0014 vlan=7\n"
#define LLDP_TWO LLDP_ONE "N chassis=4:%00%11%22%aa%bb%dd port=5:eth9 name=alpha\n"

/* Spaces to the value column of print_field_plain(): LABEL_WIDTH, the colon and one space. */
#define PAD "                              "

static bool made_netd, made_lldp;

/* Also on a failed assertion, so a leftover fixture cannot break the other tests. */
static void lldp_cleanup(void) {
        (void) unlink(lldp_fixture);
        (void) unlink(LLDP_OTHER);
        (void) unlink(LLDP_STALE);
        if (made_lldp)
                (void) rmdir(LLDP_DIR);
        if (made_netd)
                (void) rmdir("/run/netd");
}

static void test_status_lldp(void) {
        struct run_result r;
        bool absent;
        struct stat st;

        /* The rest writes to /run, which only root may. */
        if (geteuid() != 0)
                return;
        snprintf(lldp_fixture, sizeof lldp_fixture, LLDP_DIR "/%u", if_nametoindex("lo"));
        absent = stat(LLDP_DIR, &st) < 0;
        atexit(lldp_cleanup);

        /* Neither a missing directory nor an empty one is an error. */
        if (absent) {
                run(&r, "status", "lo", NULL);
                ASSERT_EQ_INT(r.exit_code, 0);
                ASSERT_TRUE(strstr(r.out, "Connected To") == NULL);
                run(&r, "--json=short", "status", "lo", NULL);
                ASSERT_EQ_INT(r.exit_code, 0);
                ASSERT_TRUE(strstr(r.out, "LLDPNeighbors") == NULL);
                made_netd = mkdir("/run/netd", 0755) == 0;
                made_lldp = mkdir(LLDP_DIR, 0755) == 0;
                ASSERT_TRUE(made_lldp);
                run(&r, "status", "lo", NULL);
                ASSERT_EQ_INT(r.exit_code, 0);
                ASSERT_TRUE(strstr(r.out, "Connected To") == NULL);
        }
        if (!absent && !S_ISDIR(st.st_mode))
                return;

        /* One neighbour: system name, description and port with its description. */
        write_file(lldp_fixture, LLDP_ONE);
        run(&r, "status", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "Connected To: sw-1 (Switch OS) on port Gi0/1 (uplink)\n") != NULL);

        /* A pattern selects the link by index, glob or name, -a shows every link. */
        run(&r, "status", "1", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: sw-1 ") != NULL);
        run(&r, "status", "l*", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: sw-1 ") != NULL);
        run(&r, "status", "-a", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "Connected To: sw-1 ") != NULL);
        run(&r, "status", "picotest-nomatch*", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_STREQ(r.out, "");

        /* The system view has no per-link neighbours. */
        run(&r, "status", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To") == NULL);

        /* Two neighbours: the first line carries the label, the next is indented, both sorted by name. */
        write_file(lldp_fixture, LLDP_TWO);
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out,
                           "Connected To: alpha on port eth9\n" PAD
                           "sw-1 (Switch OS) on port Gi0/1 (uplink)\n") != NULL);

        /* A neighbour that sent no system name, or an empty one, is n/a. */
        write_file(lldp_fixture,
                   "IFNAME=lo\nN chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1\nN chassis=4:%00%11%22%aa%bb%dd port=5:Gi0/2 name=\n");
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: n/a on port Gi0/1\n" PAD "n/a on port Gi0/2\n") != NULL);

        /* Control characters from the wire never reach the terminal. */
        write_file(lldp_fixture,
                   "IFNAME=lo\nN chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1 name=a%1b[31m%07b sysdescr=x%0ay descr=%1b[2J\n");
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: a?[31m?b (x?y) on port Gi0/1 (?[2J)\n") != NULL);
        ASSERT_TRUE(strchr(r.out, '\x1b') == NULL && strchr(r.out, '\x07') == NULL);
        run(&r, "--json=short", "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "\"SystemName\":\"a?[31m?b\"") != NULL);
        ASSERT_TRUE(strchr(r.out, '\x1b') == NULL && strchr(r.out, '\x07') == NULL);

        /* JSON: the neighbours of the link, in the shape of `lldp --json`. */
        write_file(lldp_fixture, LLDP_TWO);
        run(&r, "--json=short", "status", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out,
                           "\"LLDPNeighbors\":[{\"ChassisID\":\"00:11:22:aa:bb:dd\",\"PortID\":\"eth9\","
                           "\"SystemName\":\"alpha\"},{\"ChassisID\":\"00:11:22:aa:bb:cc\",\"PortID\":\"Gi0/1\","
                           "\"PortDescription\":\"uplink\",\"SystemName\":\"sw-1\",\"SystemDescription\":\"Switch OS\","
                           "\"EnabledCapabilities\":20,\"VlanID\":7}]}") != NULL);
        run(&r, "--json=pretty", "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "\n  \"LLDPNeighbors\" : [\n    {\n      \"ChassisID\" : ") != NULL);
        run(&r, "--json=short", "-a", "status", NULL);
        ASSERT_TRUE(STARTS(r.out, "{\"Interfaces\":[") && strstr(r.out, "\"LLDPNeighbors\":[") != NULL);

        /* Neighbours of another link, expired ones and a link without any do not show up. */
        write_file(lldp_fixture,
                   "IFNAME=lo\nN expires=1 chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1 name=old\n");
        write_file(LLDP_OTHER,
                   "IFNAME=picotest-nolink\nN chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1 name=elsewhere\n");
        run(&r, "status", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "Connected To") == NULL);
        run(&r, "--json=short", "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "LLDPNeighbors") == NULL);

        /* A file of an ifindex the link no longer has is stale, whatever its IFNAME says. */
        write_file(lldp_fixture, LLDP_ONE);
        write_file(LLDP_STALE, "IFNAME=lo\nN chassis=4:%00%11%22%aa%bb%ee port=5:Gi0/9 name=stale\n");
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: sw-1 (Switch OS) on port Gi0/1 (uplink)\n") != NULL);
        ASSERT_TRUE(strstr(r.out, "stale") == NULL);
        run(&r, "--json=short", "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "sw-1") != NULL && strstr(r.out, "stale") == NULL);
        run(&r, "--json=short", "lldp", NULL);
        ASSERT_TRUE(strstr(r.out, "sw-1") != NULL && strstr(r.out, "stale") == NULL);

        /* So is the file of this ifindex when it names another link. */
        write_file(lldp_fixture,
                   "IFNAME=picotest-nolink\nN chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1 name=wrong\n");
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To") == NULL);
        run(&r, "--json=short", "lldp", NULL);
        ASSERT_TRUE(strstr(r.out, "wrong") == NULL);

        /* Runs of spaces from the network become one in the status line. */
        write_file(lldp_fixture,
                   "IFNAME=lo\nN chassis=4:%00%11%22%aa%bb%cc port=5:Gi%20%20%20%20%200/1 "
                   "name=a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20b "
                   "sysdescr=%20%20x%20%20%20y%20%20 descr=u%20%20%20%20p\n");
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: a b ( x y ) on port Gi 0/1 (u p)\n") != NULL);

        /* A line longer than any fixed buffer: the tokens after the long ones must survive. */
        {
                char line[8192], *w = line;

                w += snprintf(line, sizeof line, "IFNAME=lo\nN chassis=7:");
                for (int i = 0; i < 255; i++)
                        w += snprintf(w, 4, "%%41");
                w += snprintf(w, 16, " port=7:");
                for (int i = 0; i < 255; i++)
                        w += snprintf(w, 4, "%%42");
                w += snprintf(w, 16, " descr=");
                for (int i = 0; i < 255; i++)
                        w += snprintf(w, 4, "%%43");
                snprintf(w, sizeof line - (size_t) (w - line), " name=late sysdescr=tail%%20OS vlan=9\n");
                ASSERT_TRUE(strlen(line) > 2048);
                write_file(lldp_fixture, line);
        }
        run(&r, "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "Connected To: late (tail OS) on port BBBB") != NULL);
        run(&r, "--json=short", "status", "lo", NULL);
        ASSERT_TRUE(strstr(r.out, "\"SystemName\":\"late\"") != NULL);
        ASSERT_TRUE(strstr(r.out, "\"SystemDescription\":\"tail OS\"") != NULL);
        ASSERT_TRUE(strstr(r.out, "\"VlanID\":9") != NULL);

        lldp_cleanup();
}

static void test_label(void) {
        struct run_result r;

        run(&r, "label", NULL);
        /* Needs IPv6; where the kernel has it the table is sorted by label. */
        if (r.exit_code == 0) {
                ASSERT_TRUE(STARTS(r.out, "LABEL ") && strstr(r.out, "PREFIX/PREFIXLEN\n") != NULL);
                run(&r, "--no-legend", "label", NULL);
                ASSERT_TRUE(strstr(r.out, "LABEL") == NULL);
        }
        run(&r, "label", "extra", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
}

static void test_failures(void) {
        struct run_result r;

        run(&r, "bogus", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);

        /* Too few and too many arguments. */
        run(&r, "up", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "reload", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "persistent-storage", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);

        /* An action netd cannot perform must not report success. */
        run(&r, "renew", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "forcerenew", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "dhcp-lease", "lo", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "edit", "x.network", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "--no-reconfigure", "reload", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);

        /* Devices are resolved before anything happens. */
        run(&r, "up", "picotest-nolink", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "down", "picotest-nolink", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "delete", "picotest-nolink", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "reconfigure", "picotest-nolink", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);

        /* A stub that parses its argument. */
        run(&r, "persistent-storage", "yes", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        run(&r, "persistent-storage", "off", NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        run(&r, "persistent-storage", "maybe", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
}

static void test_config_files(void) {
        struct run_result r;
        char path[PATH_MAX], target[16];
        FILE *f;

        run(&r, "cat", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "cat", "picotest-absent.network", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "cat", "../x.network", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "cat", "x.conf", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "mask", "x.conf", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);
        run(&r, "unmask", "dir/x.network", NULL);
        ASSERT_EQ_INT(r.exit_code, 1);

        /* The rest writes to /run, which only root may. */
        if (geteuid() != 0 || (mkdir("/run/systemd", 0755) < 0 && errno != EEXIST) ||
            (mkdir(RUNTIME_DIR, 0755) < 0 && errno != EEXIST))
                return;
        snprintf(path, sizeof path, "%s/%s", RUNTIME_DIR, FIXTURE);
        (void) unlink(path);

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        fputs("[Match]\nName=picotest0", f); /* no trailing newline */
        fclose(f);

        run(&r, "cat", FIXTURE, NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(strstr(r.out, "# " RUNTIME_DIR "/" FIXTURE "\n[Match]\nName=picotest0\n") != NULL);
        ASSERT_TRUE(r.out[strlen(r.out) - 1] == '\n');
        ASSERT_TRUE(unlink(path) == 0);

        run(&r, "--no-reload", "--runtime", "mask", FIXTURE, NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(readlink(path, target, sizeof target - 1) == (ssize_t) strlen("/dev/null"));
        run(&r, "--runtime", "--no-reload", "mask", FIXTURE, NULL);
        ASSERT_EQ_INT(r.exit_code, 0); /* already masked */

        /* A masked file is skipped by cat. */
        run(&r, "cat", FIXTURE, NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_STREQ(r.out, "");

        run(&r, "--no-reload", "unmask", FIXTURE, NULL);
        ASSERT_EQ_INT(r.exit_code, 0);
        ASSERT_TRUE(access(path, F_OK) < 0 && errno == ENOENT);
}

int main(void) {
        ASSERT_EQ_INT(sibling_binary_path("netctl", netctl_path, sizeof netctl_path), 0);

        test_accepted_options();
        test_help_version();
        test_list();
        test_json();
        test_status();
        test_lldp();
        test_status_lldp();
        test_label();
        test_failures();
        test_config_files();
        return 0;
}
