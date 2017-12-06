#pragma once

#include <stdbool.h>

#define DAEMON_OK       0
#define DAEMON_EXIT     1
#define DAEMON_ABORT    2

struct __demon_pool;
typedef struct __demon_pool demon_pool;

struct __demon_info;
typedef struct __demon_info *demon;

typedef int (*demon_phase)(void *);

demon_pool *demon_pool_new();
void demon_pool_delete(demon_pool *);

demon *demon_spawn(
    demon_pool *, demon_phase setup, demon_phase loop, demon_phase teardown, void *state);
void demon_join(demon *);
