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


#include "qpid/dispatch/general_work.h"
#include "qpid/dispatch/ctools.h"
#include "qpid/dispatch/threading.h"
#include "qpid/dispatch/alloc_pool.h"

#include <stdint.h>

// The maximum size allowed for handler arguments. This value can be increased should handlers need more memory for
// arguments.
#define QD_GENERAL_WORK_SIZE 160

struct qd_general_work_t {
    DEQ_LINKS(qd_general_work_t);
    void                       *context;
    qd_general_work_handler_t   handler;
    uint8_t overlay[QD_GENERAL_WORK_SIZE];
};

ALLOC_DECLARE(qd_general_work_t);
ALLOC_DEFINE(qd_general_work_t);
DEQ_DECLARE(qd_general_work_t, qd_general_work_list_t);

static sys_mutex_t lock;
static sys_cond_t  condition;
sys_thread_t      *thread;

static qd_general_work_list_t work_list_LH = DEQ_EMPTY;  // must hold lock
static bool need_wake_LH;  // must hold lock
static bool running_LH;    // must hold lock


static void *general_work_thread(void *context);


void qd_general_work_start(void)
{
    sys_mutex_init(&lock);
    sys_cond_init(&condition);
    sys_mutex_lock(&lock);
    running_LH = true;
    sys_mutex_unlock(&lock);
    thread = sys_thread(SYS_THREAD_GENERAL_WORK, general_work_thread, 0);
}


void qd_general_work_stop(void)
{
    // signal the background thread to stop by sending a work request with no handler

    qd_general_work_t *work = qd_general_work(0, 0, 0);
    qd_post_general_work(work);
    sys_thread_join(thread);
}

void qd_general_work_finalize(void)
{
    // discard any left over general work items, allowing them to clean up any
    // resources held by the work item

    sys_mutex_lock(&lock);
    assert(running_LH == false);   // need to call qd_general_work_stop first
    qd_general_work_t *work = DEQ_HEAD(work_list_LH);
    while (!!work) {
        DEQ_REMOVE_HEAD(work_list_LH);
        sys_mutex_unlock(&lock);
        work->handler(work->context,(void *) work->overlay, true);  // discard == true
        free_qd_general_work_t(work);
        sys_mutex_lock(&lock);
        work = DEQ_HEAD(work_list_LH);
    }
    sys_mutex_unlock(&lock);

    sys_thread_free(thread);
    sys_cond_free(&condition);
    sys_mutex_free(&lock);
}


qd_general_work_t *qd_general_work(void *context, qd_general_work_handler_t handler, size_t args_size)
{
    assert(args_size <= QD_GENERAL_WORK_SIZE);  // you need to increase QD_GENERAL_WORK_SIZE
    qd_general_work_t *work = new_qd_general_work_t();
    ZERO(work);
    work->context = context;
    work->handler = handler;
    return work;
}


void *qd_general_work_args(qd_general_work_t *work)
{
    assert(work);
    return (void *) work->overlay;
}


void qd_post_general_work(qd_general_work_t *work)
{
    bool need_wake;

    DEQ_ITEM_INIT(work);

    sys_mutex_lock(&lock);
    assert(running_LH);    // post general work after thread stopped!
    DEQ_INSERT_TAIL(work_list_LH, work);
    need_wake = need_wake_LH;
    if (need_wake) {
        need_wake_LH = false;
    }
    sys_mutex_unlock(&lock);

    if (need_wake) {
        sys_cond_signal(&condition);
    }
}


/**
 * Thread main loop
 */
static void *general_work_thread(void *context)
{
    qd_general_work_t *work = 0;

    while (true) {

        // Process one at a time, allowing other threads to run each time we take the lock
        sys_mutex_lock(&lock);
        work = DEQ_HEAD(work_list_LH);
        while (!work) {
            need_wake_LH = true;
            sys_cond_wait(&condition, &lock);
            work = DEQ_HEAD(work_list_LH);
        }

        DEQ_REMOVE_HEAD(work_list_LH);
        if (!work->handler) {
            // use a null handler as the stop thread indicator
            running_LH = false;
            sys_mutex_unlock(&lock);
            free_qd_general_work_t(work);
            return 0;
        }
        sys_mutex_unlock(&lock);

        work->handler(work->context, (void *) work->overlay, false);
        free_qd_general_work_t(work);
    }
}
