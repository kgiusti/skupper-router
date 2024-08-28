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

#include "router_core_private.h"
#include "qpid/dispatch/amqp.h"
#include "qpid/dispatch/general_work.h"

struct qdr_address_watch_t {
    DEQ_LINKS(struct qdr_address_watch_t);
    DEQ_LINKS_N(PER_ADDRESS, struct qdr_address_watch_t);
    qdr_watch_handle_t          watch_handle;
    qdr_address_t              *addr;
    qdr_address_watch_update_t  on_update;
    qdr_address_watch_cancel_t  on_cancel;
    void                       *context;
};

ALLOC_DECLARE(qdr_address_watch_t);
ALLOC_DEFINE(qdr_address_watch_t);

static void qdr_watch_invoker(void *context, void *args, bool discard);
static void qdr_watch_cancel_invoker(void *context, void *args, bool discard);
static void qdr_core_watch_address_CT(qdr_core_t *core, qdr_action_t *action, bool discard);
static void qdr_core_unwatch_address_CT(qdr_core_t *core, qdr_action_t *action, bool discard);
static void qdr_address_watch_free_CT(qdr_core_t *core, qdr_address_watch_t *watch);

//==================================================================================
// Core Interface Functions
//==================================================================================
qdr_watch_handle_t qdr_core_watch_address(qdr_core_t                 *core,
                                          const char                 *address,
                                          char                        aclass,
                                          qd_address_treatment_t      treatment_hint,
                                          qdr_address_watch_update_t  on_update,
                                          qdr_address_watch_cancel_t  on_cancel,
                                          void                       *context)
{
    static sys_atomic_t next_handle;
    qdr_action_t *action = qdr_action(qdr_core_watch_address_CT, "watch_address");

    action->args.io.address        = qdr_field(address);
    action->args.io.address_class  = aclass;
    action->args.io.treatment      = treatment_hint;
    action->args.io.watch_handler  = on_update;
    action->args.io.cancel_handler = on_cancel;
    action->args.io.context        = context;
    action->args.io.value32_1      = sys_atomic_inc(&next_handle);

    qdr_watch_handle_t retval = action->args.io.value32_1;

    qdr_action_enqueue(core, action);
    return retval;
}


void qdr_core_unwatch_address(qdr_core_t *core, qdr_watch_handle_t handle)
{
    qdr_action_t *action = qdr_action(qdr_core_unwatch_address_CT, "unwatch_address");

    action->args.io.value32_1 = handle;
    qdr_action_enqueue(core, action);
}


//==================================================================================
// In-Core API Functions
//==================================================================================

// arguments for the qdr_watch_invoker() update handler work item
//
typedef struct qdr_watch_invoker_args_t qdr_watch_invoker_args_t;
struct qdr_watch_invoker_args_t {
    qdr_address_watch_update_t   watch_update_handler;
    uint32_t                     local_consumers;
    uint32_t                     in_proc_consumers;
    uint32_t                     remote_consumers;
    uint32_t                     local_producers;
};

// arguments for the qdr_watch_cancel_invoker() cancel handler work item
//
typedef struct qdr_watch_cancel_invoker_args_t qdr_watch_cancel_invoker_args_t;
struct qdr_watch_cancel_invoker_args_t {
    qdr_address_watch_cancel_t   watch_cancel_handler;
};


void qdr_trigger_address_watch_CT(qdr_core_t *core, qdr_address_t *addr)
{
    qdr_address_watch_t *watch = DEQ_HEAD(addr->watches);

    while (!!watch) {
        qd_general_work_t *work = qd_general_work(watch->context,
                                                  qdr_watch_invoker,
                                                  sizeof(qdr_watch_invoker_args_t));
        qdr_watch_invoker_args_t *args = (qdr_watch_invoker_args_t *) qd_general_work_args(work);
        args->watch_update_handler = watch->on_update;
        args->local_consumers      = DEQ_SIZE(addr->rlinks);
        args->in_proc_consumers    = DEQ_SIZE(addr->subscriptions);
        args->remote_consumers     = qd_bitmask_cardinality(addr->rnodes);
        args->local_producers      = DEQ_SIZE(addr->inlinks);
        qd_post_general_work(work);
        watch = DEQ_NEXT_N(PER_ADDRESS, watch);
    }
}

void qdr_address_watch_shutdown(qdr_core_t *core)
{
    qdr_address_watch_t *watch = DEQ_HEAD(core->addr_watches);
    while (!!watch) {
        DEQ_REMOVE(core->addr_watches, watch);
        qdr_address_watch_free_CT(core, watch);
        watch = DEQ_HEAD(core->addr_watches);
    }
}


//==================================================================================
// Local Functions
//==================================================================================
static void qdr_address_watch_free_CT(qdr_core_t *core, qdr_address_watch_t *watch)
{
    DEQ_REMOVE_N(PER_ADDRESS, watch->addr->watches, watch);
    if (DEQ_SIZE(watch->addr->watches) == 0) {
        qdrc_event_addr_raise(core, QDRC_EVENT_ADDR_WATCH_OFF, watch->addr);
    }

    watch->addr->ref_count--;
    qdr_check_addr_CT(core, watch->addr);
    free_qdr_address_watch_t(watch);
}


static void qdr_watch_invoker(void *context, void *args, bool discard)
{
    if (!discard) {
        qdr_watch_invoker_args_t *iargs = (qdr_watch_invoker_args_t *) args;
        iargs->watch_update_handler(context,
                                   iargs->local_consumers, iargs->in_proc_consumers, iargs->remote_consumers, iargs->local_producers);
    }
}


static void qdr_watch_cancel_invoker(void *context, void *args, bool discard)
{
    // @TODO(kgiusti): pass discard flag to handler to allow it to clean up the context
    qdr_watch_cancel_invoker_args_t *iargs = (qdr_watch_cancel_invoker_args_t *) args;
    iargs->watch_cancel_handler(context);
}


static void qdr_core_watch_address_CT(qdr_core_t *core, qdr_action_t *action, bool discard)
{
    if (!discard) {
        qd_iterator_t *iter = qdr_field_iterator(action->args.io.address);
        qd_iterator_annotate_prefix(iter, action->args.io.address_class);
        qd_iterator_reset_view(iter, ITER_VIEW_ADDRESS_HASH);
        qdr_address_t *addr = 0;

        qd_hash_retrieve(core->addr_hash, iter, (void**) &addr);
        if (!addr) {
            qdr_address_config_t   *addr_config;
            qd_address_treatment_t  treatment =
                qdr_treatment_for_address_hash_with_default_CT(core, iter, action->args.io.treatment, &addr_config);

            addr = qdr_address_CT(core, treatment, addr_config);
            if (!!addr) {
                qd_hash_insert(core->addr_hash, iter, addr, &addr->hash_handle);
                DEQ_ITEM_INIT(addr);
                DEQ_INSERT_TAIL(core->addrs, addr);
            } else {
                qd_log(LOG_ROUTER_CORE, QD_LOG_CRITICAL, "Failed to create address for watch");
                assert(false);
            }
        }

        if (!!addr) {
            qdr_address_watch_t *watch = new_qdr_address_watch_t();
            ZERO(watch);
            watch->watch_handle = action->args.io.value32_1;
            watch->addr         = addr;
            watch->on_update    = action->args.io.watch_handler;
            watch->on_cancel    = action->args.io.cancel_handler;
            watch->context      = action->args.io.context;
            DEQ_INSERT_TAIL(core->addr_watches, watch);

            DEQ_INSERT_TAIL_N(PER_ADDRESS, addr->watches, watch);
            addr->ref_count++;

            //
            // Raise a core event to notify interested parties that this address is being watched.
            //
            if (DEQ_SIZE(addr->watches) == 1) {
                qdrc_event_addr_raise(core, QDRC_EVENT_ADDR_WATCH_ON, addr);
            }

            //
            // Trigger a watch callback for an initial snapshot.
            //
            qdr_trigger_address_watch_CT(core, addr);
        }
    }
    qdr_field_free(action->args.io.address);
}


static void qdr_core_unwatch_address_CT(qdr_core_t *core, qdr_action_t *action, bool discard)
{
    if (!discard) {
        qdr_watch_handle_t watch_handle = action->args.io.value32_1;

        qdr_address_watch_t *watch = DEQ_HEAD(core->addr_watches);
        while (!!watch) {
            if (watch->watch_handle == watch_handle) {
                DEQ_REMOVE(core->addr_watches, watch);
                if (!!watch->on_cancel) {
                    qd_general_work_t *work = qd_general_work(watch->context,
                                                              qdr_watch_cancel_invoker,
                                                              sizeof(qdr_watch_cancel_invoker_args_t));
                    qdr_watch_cancel_invoker_args_t *args = (qdr_watch_cancel_invoker_args_t *) qd_general_work_args(work);
                    args->watch_cancel_handler = watch->on_cancel;
                    qd_post_general_work(work);
                }
                qdr_address_watch_free_CT(core, watch);
                break;
            }
            watch = DEQ_NEXT(watch);
        }
    }
}
