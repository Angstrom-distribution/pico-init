/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The drop-in contract of the built libsystemd.so, checked on the real
 * file a consumer gets rather than on the build recipe that made it:
 * DT_SONAME is libsystemd.so.0; the ELF version-definition table is
 * exactly the node set of libsystemd.sym; every symbol the version script
 * lists resolves at its node through dlvsym(), which is the lookup a
 * binary linked against real libsystemd performs
 * (sd_bus_message_append@LIBSYSTEMD_209); and the helpers behind
 * `local: *` stay hidden. dlopen() with RTLD_NOW is the undefined-symbol
 * check -- every relocation resolves up front or the load fails, the same
 * way it would on the target.
 *
 * argv[1]: the built shared object; argv[2]: the version script it was
 * linked with.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test-util.h"

#define MAX_NODES 64
#define MAX_SYMBOLS 4096

/* The ELF class of the running binary is the class of the .so under test:
 * both are native builds of the same tree. */
typedef ElfW(Ehdr) Ehdr;
typedef ElfW(Shdr) Shdr;
typedef ElfW(Dyn) Dyn;
typedef ElfW(Verdef) Verdef;
typedef ElfW(Verdaux) Verdaux;

static const char *nodes[MAX_NODES];
static size_t n_nodes;
static const char *symbols[MAX_SYMBOLS];
static const char *symbol_nodes[MAX_SYMBOLS];
static size_t n_symbols;

static char *xstrdup(const char *s) {
        char *r = strdup(s);
        ASSERT_TRUE(r);
        return r;
}

static char *trim(char *s) {
        char *e;

        while (*s == ' ' || *s == '\t')
                s++;
        e = s + strlen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r'))
                *--e = '\0';
        return s;
}

/* Reads the version script's node names and per-node symbol lists. Block
 * comments may span lines (the generated file's header does). */
static void parse_version_script(const char *path) {
        FILE *f = fopen(path, "r");
        char line[512];
        const char *cur = NULL;
        int in_comment = 0;

        ASSERT_TRUE(f);
        while (fgets(line, sizeof line, f)) {
                char *s = line, *p;

                if (in_comment) {
                        p = strstr(s, "*/");
                        if (!p)
                                continue;
                        in_comment = 0;
                        s = p + 2;
                }
                while ((p = strstr(s, "/*"))) {
                        char *e = strstr(p + 2, "*/");
                        if (!e) {
                                *p = '\0';
                                in_comment = 1;
                                break;
                        }
                        memmove(p, e + 2, strlen(e + 2) + 1);
                }
                s = trim(s);
                if (!*s || strcmp(s, "global:") == 0 || strcmp(s, "local:") == 0 || strcmp(s, "*;") == 0)
                        continue;

                p = strchr(s, '{');
                if (p) {
                        ASSERT_TRUE(!cur);
                        *p = '\0';
                        ASSERT_TRUE(n_nodes < MAX_NODES);
                        cur = nodes[n_nodes++] = xstrdup(trim(s));
                        continue;
                }
                if (*s == '}') {
                        ASSERT_TRUE(cur);
                        cur = NULL;
                        continue;
                }
                p = strchr(s, ';');
                ASSERT_TRUE(cur && p);
                *p = '\0';
                ASSERT_TRUE(n_symbols < MAX_SYMBOLS);
                symbols[n_symbols] = xstrdup(trim(s));
                symbol_nodes[n_symbols] = cur;
                n_symbols++;
        }
        ASSERT_TRUE(!cur);
        fclose(f);
}

static void *read_at(FILE *f, long off, size_t n) {
        void *buf = malloc(n ? n : 1);

        ASSERT_TRUE(buf);
        ASSERT_TRUE(fseek(f, off, SEEK_SET) == 0);
        ASSERT_TRUE(fread(buf, 1, n, f) == n);
        return buf;
}

static void *read_section(FILE *f, const Shdr *sh) {
        return read_at(f, (long) sh->sh_offset, sh->sh_size);
}

/* DT_SONAME and the SHT_GNU_verdef names, straight from the file on disk:
 * independent of how (or whether) the dynamic loader relocates the
 * in-memory dynamic section, which differs per architecture. */
static void check_elf(const char *path, const char *expect_soname) {
        FILE *f = fopen(path, "rb");
        Ehdr *eh;
        Shdr *shdrs;
        const Shdr *dyn_sh = NULL, *verdef_sh = NULL;
        const char *soname = NULL;
        size_t n_verdef = 0, matched = 0;
        char *verdef_names[MAX_NODES];

        ASSERT_TRUE(f);
        eh = read_at(f, 0, sizeof *eh);
        ASSERT_TRUE(memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0);
        ASSERT_EQ_INT(eh->e_type, ET_DYN);
        ASSERT_EQ_INT(eh->e_shentsize, sizeof(Shdr));
        shdrs = read_at(f, (long) eh->e_shoff, (size_t) eh->e_shnum * sizeof *shdrs);

        for (size_t i = 0; i < eh->e_shnum; i++) {
                if (shdrs[i].sh_type == SHT_DYNAMIC)
                        dyn_sh = &shdrs[i];
                else if (shdrs[i].sh_type == SHT_GNU_verdef)
                        verdef_sh = &shdrs[i];
        }
        ASSERT_TRUE(dyn_sh);
        ASSERT_TRUE(verdef_sh);

        {
                Dyn *dyn = read_section(f, dyn_sh);
                const char *strtab = read_section(f, &shdrs[dyn_sh->sh_link]);
                size_t n = dyn_sh->sh_size / sizeof *dyn;

                for (size_t i = 0; i < n && dyn[i].d_tag != DT_NULL; i++)
                        if (dyn[i].d_tag == DT_SONAME) {
                                ASSERT_TRUE(dyn[i].d_un.d_val < shdrs[dyn_sh->sh_link].sh_size);
                                soname = strtab + dyn[i].d_un.d_val;
                        }
        }
        ASSERT_TRUE(soname);
        ASSERT_STREQ(soname, expect_soname);

        {
                char *data = read_section(f, verdef_sh);
                const char *vstr = read_section(f, &shdrs[verdef_sh->sh_link]);
                size_t off = 0;

                /* sh_info is the entry count; the first entry is the base
                 * version (VER_FLG_BASE, named after the SONAME), not a node. */
                for (size_t i = 0; i < verdef_sh->sh_info; i++) {
                        Verdef *vd = (Verdef *) (void *) (data + off);
                        Verdaux *va = (Verdaux *) (void *) ((char *) vd + vd->vd_aux);

                        ASSERT_TRUE(off + sizeof *vd <= verdef_sh->sh_size);
                        ASSERT_EQ_INT(vd->vd_version, 1);
                        if (!(vd->vd_flags & VER_FLG_BASE)) {
                                ASSERT_TRUE(n_verdef < MAX_NODES);
                                verdef_names[n_verdef++] = xstrdup(vstr + va->vda_name);
                        }
                        if (vd->vd_next == 0)
                                break;
                        off += vd->vd_next;
                }
        }

        for (size_t i = 0; i < n_nodes; i++) {
                int found = 0;
                for (size_t j = 0; j < n_verdef; j++)
                        if (strcmp(nodes[i], verdef_names[j]) == 0)
                                found = 1;
                if (!found)
                        fprintf(stderr, "node %s in the version script but not in %s\n", nodes[i], path);
                matched += found;
        }
        for (size_t j = 0; j < n_verdef; j++) {
                int found = 0;
                for (size_t i = 0; i < n_nodes; i++)
                        if (strcmp(nodes[i], verdef_names[j]) == 0)
                                found = 1;
                if (!found)
                        fprintf(stderr,
                                "version %s in %s but not in the version script\n",
                                verdef_names[j],
                                path);
        }
        ASSERT_EQ_INT(matched, n_nodes);
        ASSERT_EQ_INT(n_verdef, n_nodes);
        fclose(f);
}

static void check_dlopen(const char *path) {
        void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        size_t missing = 0;
        static const char * const hidden[] = {
                /* one per link_whole'd or private family: logd's ring
                 * reader, the HMAC helper, sd-event/sd-device/sd-journal
                 * internals */
                "logd_ring_read",  "hmac_sha256",           "event_source_new",
                "device_new_bare", "journal_current_entry",
        };

        if (!h) {
                fprintf(stderr, "dlopen(%s) failed: %s\n", path, dlerror());
                exit(1);
        }

        for (size_t i = 0; i < n_symbols; i++)
                if (!dlvsym(h, symbols[i], symbol_nodes[i])) {
                        fprintf(stderr, "%s@%s not resolvable\n", symbols[i], symbol_nodes[i]);
                        missing++;
                }
        ASSERT_EQ_INT(missing, 0);

        /* An unversioned lookup, the shape dlsym()-driven consumers use,
         * lands on the default version. */
        ASSERT_TRUE(dlsym(h, "sd_bus_message_append"));
        ASSERT_TRUE(dlsym(h, "sd_journal_open"));
        ASSERT_TRUE(dlsym(h, "sd_network_monitor_new"));

        for (size_t i = 0; i < sizeof hidden / sizeof hidden[0]; i++)
                if (dlsym(h, hidden[i])) {
                        fprintf(stderr, "%s leaks out of the shared object\n", hidden[i]);
                        exit(1);
                }

        dlclose(h);
}

int main(int argc, char **argv) {
        ASSERT_EQ_INT(argc, 3);

        parse_version_script(argv[2]);
        ASSERT_TRUE(n_nodes > 0);
        ASSERT_TRUE(n_symbols > 0);

        check_elf(argv[1], "libsystemd.so.0");
        check_dlopen(argv[1]);

        printf("test-libsystemd-so: %s: SONAME ok, %zu version nodes, %zu versioned symbols resolve\n",
               argv[1],
               n_nodes,
               n_symbols);
        return 0;
}
