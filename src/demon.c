#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "demon.h"

#define atomic_load(ptr) __atomic_load_n(ptr, __ATOMIC_SEQ_CST)
#define atomic_store(ptr,val) __atomic_store_n(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_exchange(ptr, val) __atomic_exchange_n(ptr, val, __ATOMIC_SEQ_CST)

typedef struct __demon_info demon_info;

typedef struct __demon_node {
  demon_info *d;
  struct __demon_node *next;
  struct __demon_node *prev;
} demon_node;

struct __demon_pool {
  pthread_mutex_t lock;
  demon_node *head;
};

struct __demon_info {
  volatile bool halt;
  volatile bool running;
  demon_node *node;
  demon_pool *pool;
  demon_info **handle;

  void *state;
  demon_phase setup;
  demon_phase loop;
  demon_phase teardown;
};

demon_pool *demon_pool_new()
{
  demon_pool *pool = (demon_pool *)malloc(sizeof(demon_pool));
  if (pool == NULL) {
    perror("malloc");
    return NULL;
  }

  int err;
  if ((err = pthread_mutex_init(&pool->lock, NULL)) != 0) {
    debug("could not initialize mutex: %s\n", strerror(err));
    free(pool);
    return NULL;
  }

  pool->head = NULL;

  return pool;
}

void demon_pool_delete(demon_pool *pool)
{
  int err;
  if ((err = pthread_mutex_lock(&pool->lock)) != 0) {
    debug("could not lock mutex, possible memory leak: %s\n", strerror(err));
  }
  for (demon_node *node = pool->head; node != NULL; node = node->next) {
    atomic_store(&node->d->halt, true);
  }
  free(pool);
}

static bool demon_pool_add(demon_pool *pool, demon_info *d)
{
  bool ok = true;
  int err;
  if ((err = pthread_mutex_lock(&pool->lock)) != 0) {
    debug("could not aquire mutex: %s\n", strerror(err));
    return false;
  }

  demon_node *node = (demon_node *)malloc(sizeof(demon_node));
  if (node == NULL) {
    perror("malloc");
    ok = false;
    goto cleanup;
  }

  d->pool = pool;
  d->node = node;
  node->d = d;
  node->next = NULL;
  node->prev = NULL;

  if (pool->head != NULL) {
    pool->head->prev = node;
    node->next = pool->head;
  }
  pool->head = node;

cleanup:
  pthread_mutex_unlock(&pool->lock);
  return ok;
}

static bool demon_pool_remove(demon_info *d)
{
  demon_pool *pool = d->pool;

  int err;
  if ((err = pthread_mutex_lock(&pool->lock)) != 0) {
    debug("could not aquire mutex: %s\n", strerror(err));
    return false;
  }

  demon_node *node = d->node;
  if (node != NULL) {
    // Not already removed
    if (node->prev) {
      node->prev->next = node->next;
    }
    if (node->next) {
      node->next->prev = node->prev;
    }
    if (node == pool->head) {
      pool->head = node->next;
    }
    d->node = NULL;
    free(node);
  }

  pthread_mutex_unlock(&pool->lock);
  return true;
}

static void *demon_thread(void *void_arg)
{
  demon_info *d = (demon_info *)void_arg;

  if (d->setup) {
    switch (d->setup(d->state)) {
    case DAEMON_OK:
      break;
    case DAEMON_EXIT:
      goto teardown;
    case DAEMON_ABORT:
      debug("daemon aborted in setup phase, exiting without teardown\n");
      goto exit;
    default:
      debug("daemon setup returned unknown error code, aborting\n");
      goto exit;
    }
  }

  if (d->loop) {
    while (!atomic_load(&d->halt)) {
      switch (d->loop(d->state)) {
      case DAEMON_OK:
        break;
      case DAEMON_EXIT:
        debug("daemon exiting from loop\n");
        goto teardown;
      case DAEMON_ABORT:
        debug("daemon aborted during loop, beginning teardown\n");
        goto teardown;
      default:
        debug("daemon loop returned unknown error code, aborting\n");
        goto teardown;
      }
    }
  }

teardown:
  if (d->teardown) {
    d->teardown(d->state);
  }

exit:
  if (atomic_exchange(d->handle, NULL) == NULL) {
    // Handle was set to NULL by join, join will take care of freeing
    // Tell join we're done
    atomic_store(&d->running, false);
  } else {
    // No join, we're responsible for freeing memory
    demon_pool_remove(d);
    free(d->handle);
    free(d);
  }

  return NULL;
}

demon *demon_spawn(
  demon_pool *pool, demon_phase setup, demon_phase loop, demon_phase teardown, void *state)
{
  demon_info *d = (demon_info *)malloc(sizeof(demon_info));
  if (d == NULL) {
    perror("malloc");
    return NULL;
  }

  d->running = true;
  d->halt = false;
  d->setup = setup;
  d->loop = loop;
  d->teardown = teardown;
  d->state = state;
  d->pool = pool;
  d->node = NULL;

  demon_info **handle = (demon_info **)malloc(sizeof(demon_info *));
  if (handle == NULL) {
    perror("malloc");
    goto err_handle;
  }
  d->handle = handle;
  *handle = d;

  if (!demon_pool_add(pool, d)) {
    debug("error adding demon to pool\n");
    goto err_list_append;
  }

  int pthread_errno;
  pthread_t thread;
  if ((pthread_errno = pthread_create(&thread, NULL, demon_thread, d)) != 0) {
    debug("error creating demon thread: %s\n", strerror(pthread_errno));
    goto err_thread_create;
  }
  if ((pthread_errno = pthread_detach(thread)) != 0) {
    debug("error detaching demon thread: %s\n", strerror(pthread_errno));
    goto err_thread_detach;
  }
  return handle;

err_thread_detach:
err_thread_create:
err_list_append:
  free(handle);
err_handle:
  free(d);
  return NULL;
}

void demon_join(demon_info **handle)
{
  demon_info *d;
  if ((d = atomic_exchange(handle, NULL)) != NULL) {
    atomic_store(&d->halt, true);
    while (atomic_load(&d->running));
    demon_pool_remove(d);
    free(handle);
    free(d);
  }
  // Else handle set to null by the thread, means the thread is already exiting
}
