#ifndef __sys_threading_h__
#define __sys_threading_h__ 1
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**@file
 * Threading and locking API.
 */

#include <pthread.h>

typedef struct sys_mutex_t sys_mutex_t;
struct sys_mutex_t {
    pthread_mutex_t mutex;
};

void sys_mutex_init(sys_mutex_t *mutex);
void sys_mutex_free(sys_mutex_t *mutex);
void sys_mutex_lock(sys_mutex_t *mutex);
void sys_mutex_unlock(sys_mutex_t *mutex);

typedef struct sys_cond_t sys_cond_t;
struct sys_cond_t {
    pthread_cond_t cond;
};

void sys_cond_init(sys_cond_t *cond);
void sys_cond_free(sys_cond_t *cond);
void sys_cond_wait(sys_cond_t *cond, sys_mutex_t *held_mutex);
void sys_cond_signal(sys_cond_t *cond);
void sys_cond_signal_all(sys_cond_t *cond);


typedef struct sys_rwlock_t sys_rwlock_t;
struct sys_rwlock_t {
    pthread_rwlock_t lock;
};

void sys_rwlock_init(sys_rwlock_t *lock);
void sys_rwlock_free(sys_rwlock_t *lock);
void sys_rwlock_wrlock(sys_rwlock_t *lock);
void sys_rwlock_rdlock(sys_rwlock_t *lock);
void sys_rwlock_unlock(sys_rwlock_t *lock);

typedef enum {
    SYS_THREAD_MAIN,
    SYS_THREAD_CORE,
    SYS_THREAD_PROACTOR,
    SYS_THREAD_VFLOW,
    SYS_THREAD_LWS_HTTP,
    // add new thread roles here and update _thread_names in threading.c
    SYS_THREAD_ROLE_COUNT
} sys_thread_role_t;

// Proactor threads operate in different modes depending on the proactor event being handled by the thread. The proactor
// makes certain thread-safety guarantees depending on the mode:
//
// - MODE_PROACTOR: A proactor-global event. Only one thread will be running in this mode. This thread runs currently
//   with other threads which may be in MODE_IO and MODE_LISTENER. This mode is used to handle timer expiration, as well
//   as other events not associated with proactor connections/listeners. Must not do proactor connection I/O or
//   manipulate proactor listeners while in this mode.
//
// - MODE_IO: May run concurrently with other threads running in MODE_IO/TIMER/LISTENER. The thread can safely do I/O
//   only on the connection associated with the event. Must not do I/O on other proactor connections. Must not
//   manipulate proactor listeners or run timer handlers.
//
// - MODE_LISTENER: May run concurrently with other threads running in MODE_IO/TIMER/LISTENER. The
//   thread can safely manipulate the listener associated with the event, including accepting/starting new
//   connections. Must not do connection I/O or access any other listener instances or timer handlers.
//
// Note well: any proactor API calls that are explicitly marked as "thread-safe" CAN safely be used from any thread
// regardless of mode.
//
typedef enum {
    SYS_THREAD_MODE_NONE     = 0,  // non-proactor thread default mode
    SYS_THREAD_MODE_PROACTOR = 0x01,
    SYS_THREAD_MODE_IO       = 0x02,
    SYS_THREAD_MODE_LISTENER = 0x04,

    // syntactic sugar:
    SYS_THREAD_MODE_TIMER = SYS_THREAD_MODE_PROACTOR,
} sys_thread_mode_t;

typedef struct sys_thread_t sys_thread_t;

sys_thread_t *sys_thread(sys_thread_role_t role, void *(*run_function)(void *), void *arg);
void          sys_thread_free(sys_thread_t *thread);
void          sys_thread_join(sys_thread_t *thread);
sys_thread_t *sys_thread_self(void);

// these functions will use the current thread if passed 0:
sys_thread_role_t sys_thread_role(const sys_thread_t *);
const char       *sys_thread_name(const sys_thread_t *thread);

// these functions are only safe to operate on the current thread
sys_thread_mode_t sys_thread_mode(void);
sys_thread_mode_t sys_thread_set_mode(sys_thread_mode_t new_mode);  // returns previous mode

#ifdef NDEBUG
#define ASSERT_THREAD_IS(ROLE)
#define ASSERT_THREAD_IS_NOT(ROLE)
#define ASSERT_THREAD_MODE(MASK)
#else
#include <assert.h>
#define ASSERT_THREAD_IS(ROLE)                \
    do {                                      \
        assert(sys_thread_role(0) == (ROLE)); \
    } while (0)

#define ASSERT_THREAD_IS_NOT(ROLE)            \
    do {                                      \
        assert(sys_thread_role(0) != (ROLE)); \
    } while (0)

#define ASSERT_THREAD_MODE(MASK)                \
    do {                                        \
        assert(!!(sys_thread_mode() & (MASK))); \
    } while (0)
#endif  // NDEBUG

// for testing/debug only
//
char *test_threading_roles_names(void *context);

#endif  // __sys_threading_h__
