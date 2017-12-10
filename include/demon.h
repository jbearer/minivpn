/**
 * \file
 *
 * This module provides an infrastructure for smart background threads.
 *
 * Threads created here are called demons. They are state machines composed of non-blocking states
 * which can be interrupted and closed. They are responsive to a close command whenever they
 * transition between states. They can also exit of their own accord, in which case they immediately
 * release all resources even if they are never joined. Joining a demon which has already exited
 * is safe and succeeds immediately.
 */

#pragma once

#include <stdbool.h>

#define DAEMON_OK       0
#define DAEMON_EXIT     1
#define DAEMON_ABORT    2

struct __demon_pool;

/**
 * \brief A demon_pool is a container which manages a set of demons.
 * \detail The demon_pool maintains a handle to each demon it creates so that unjoined demons can be
 * stopped and freed when the pool is deleted.
 */
typedef struct __demon_pool demon_pool;

struct __demon_info;
/**
 * \brief A demon is a lightweight background task which is capable of being stopped or of exiting
 * on its own.
 */
typedef struct __demon_info *demon;

/**
 * \brief The type of a state in the demon state machine.
 * \detail A demon phase takes as argument the mutable state for that demon. It returns a code
 * indicating how the demon should proceed. Valid return codes are:
 *
 *  * #DAEMON_OK: proceed normally to the next phase
 *  * #DAEMON_EXIT: break out of the state machine, proceeding to the teardown phase and then
 *      exiting.
 *  * #DAEMON_ABORT: break out of the state machine with an error, proceeding to the teardown phase
 *      only if the setup phase has completed successfully.
 */
typedef int (*demon_phase)(void *);

/**
 * \brief Allocate and initialize a demon_pool.
 *
 * \return A pointer to the new pool, or NULL in case of failure.
 */
demon_pool *demon_pool_new();

/**
 * \brief Deallocate a demon pool.
 * \detail If there are any unjoined demons in the pool, they are joined before the pool is
 * deallocated. Subsequent operations on those demons or on the pool itself are undefined.
 */
void demon_pool_delete(demon_pool *);

/**
 * \brief Create and start a new demon.
 * \detail Any of the state machine phases can be NULL, in which case that phase of the state
 * machine is simply skipped.
 *
 * \return A pointer to the new demon, suitable for passing to demon_join, or NULL on failure.
 *
 * \param pool The pool to which the new demon will belong.
 * \param setup The setup phase of the state machine. Called once immediately after the demon starts.
 * \param loop The loop phase of the state machine. Called repeatedly after the setup phase
 * completes until it returns DAEMON_EXIT or DAEMON_ABORT or the demon is interrupted by demon_join().
 * \param teardown Phase called before shutting down the demon.
 * \param state Mutable state upon which any of the phases of the state machine can act.
 */
demon *demon_spawn(
    demon_pool *pool, demon_phase setup, demon_phase loop, demon_phase teardown, void *state);

/**
 * \brief Interrupt and deallocate a demon.
 * \detail If the given demon is still running, instruct it to stop and block until it responds. It
 * will resond to the command the next time it returns from a state. Once the demon stops, its
 * resources are freed. If the demon has already exited, this function is a noop.
 */
void demon_join(demon *);
