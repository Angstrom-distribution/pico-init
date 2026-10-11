/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Target units: a named synchronisation point with no process of its own.
 * Starting a target means "everything it pulls in has been started"; the job
 * engine does the work by walking the target's Wants=/Requires= and ordering
 * edges.
 *
 * Targets exist because the boot transaction needs a root. pico-init follows
 * upstream's model: default.target is the root, WantedBy= is honoured via
 * real .wants/ symlink directories, and preset files decide what is enabled by
 * default, so unmodified upstream unit files behave as written.
 */

#pragma once

#include "unit.h"

typedef enum TargetState {
        TARGET_DEAD,
        TARGET_ACTIVE,
        _TARGET_STATE_MAX,
} TargetState;

typedef struct Target {
        Unit unit; /* must be first: a Target* is a Unit* */

        TargetState state;
} Target;

/* downcast/upcast helpers, valid because Unit is the first member */
#define TARGET(u) ((Target *) (u))
#define TARGET_UNIT(t) (&(t)->unit)

/* --- target.c --- */
int target_start(Target *t); /* DEAD -> ACTIVE; no process is involved */
int target_stop(Target *t);  /* ACTIVE -> DEAD */

const char *target_state_to_string(TargetState s);
