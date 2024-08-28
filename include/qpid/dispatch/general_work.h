#ifndef __general_work_h__
#define __general_work_h__ 1
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

#include <stddef.h>
#include <stdbool.h>


//
// General Work
//
// The following API can be used to post work to be executed on a background thread.  Work handlers are run serially in
// the order they are posted (no two work items will run at the same time).  The background thread is non-Proactor and
// can run at the same time as Proactor threads (I/O and qd_timers) as well as router core and other system threads.
//

typedef struct qd_general_work_t qd_general_work_t;

/**
 * General work handler
 *
 * The signature of the function that is run on the background thread
 *
 * If the discard parameter to the handler is true the router is in the process of shutting down and cleaning up any
 * outstanding general work items. At this point all threads have been shutdown and the handler must avoid scheduling
 * any further work and should simply release any resources held by the args parameter.
 *
 * @param context the context parameter passed to qd_general_work() constructor
 * @param args a pointer to memory holding the arguments set via qd_general_work_args()
 * @param discard True if the router is shutting down and the handler should discard the work.
 */
typedef void (*qd_general_work_handler_t) (void *context, void *args, bool discard);

/**
 * Create a new general work request
 *
 * @param context supplied by caller, passed to handler
 * @param handler the function to run
 * @param args_size the amount of memory needed for handler arguments
 * @return a pointer to an initialized qd_general_work_t instance (never null)
 */
qd_general_work_t *qd_general_work(void *context, qd_general_work_handler_t handler, size_t args_size);

/**
 * Access the work item's memory for handler arguments
 *
 * Use this function to initialize the handler's input parameters before posting the work item. It is expected that the
 * caller will cast the return value to a pointer to the appropriate structure that holds the handler's parameters. This
 * pointer will be passed in the args parameter to the handler function.
 *
 * The returned pointer must not be accessed after the work item has been scheduled (on return from
 * qd_post_general_work())
 *
 * @param work the general work instance
 * @return address of the start of argument memory. The amount of memory returned will be the value of the args_size
 * parameter passed to qd_general_work()
 */
void *qd_general_work_args(qd_general_work_t *work);

/**
 * Schedule the work item to run on the general work thread.
 *
 * The caller must not reference work on return from this call.
 *
 * @param work the work item to schedule
 */
void qd_post_general_work(qd_general_work_t *work);

/**
 * Start the general work thread
 */
void qd_general_work_start(void);

/**
 * Stop the general work thread.
 *
 * Blocks caller until thread has stopped. Work callbacks will cease being invoked on return to the caller.
 *
 */
void qd_general_work_stop(void);

/**
 * Free all resources associated with general work
 *
 * During this call any pending work items that have been submitted after qd_general_work_stop() has been called will be
 * invoked with the discard flag true.
 *
 */
void qd_general_work_finalize(void);

#endif // __general_work_h__
