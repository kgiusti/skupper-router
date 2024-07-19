#ifndef __tls_private_h__
#define __tls_private__ 1
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

#include "qpid/dispatch/ctools.h"
#include "qpid/dispatch/atomic.h"
#include "qpid/dispatch/threading.h"
#include "qpid/dispatch/log.h"

typedef struct qd_tls_context_t qd_tls_context_t;
typedef struct pn_tls_t pn_tls_t;
typedef struct pn_tls_config_t pn_tls_config_t;

/**
 * Context for a single per-connection TLS data stream
 */
struct qd_tls2_session_t {
    qd_tls2_domain_t       *tls_domain;      // parent
    pn_tls_t              *pn_tls_session;
    void                  *user_context;
    qd_tls2_session_on_secure_cb_t *on_secure_cb;
    uint64_t               conn_id;
    qd_log_module_t        log_module;

    bool                   tls_has_output;
    bool                   tls_error;
    bool                   output_eos;       // pn_tls_close_output() called
    bool                   raw_read_drained; // raw conn read closed and all buffer read
    bool                   input_drained;    // no more decrypted output, raw conn read closed
    bool                   output_flushed;   // encrypt done, raw conn write closed

    uint64_t encrypted_output_bytes;
    uint64_t encrypted_input_bytes;
};

/**
 * Context for a TLS Domain configuration object.
 * Factory for creating qd_tls2_session_t instances.
 */
struct qd_tls2_domain_t {
    DEQ_LINKS(qd_tls2_domain_t);   // parent qd_tls2_t domain list
    char            *name;
    char            *ssl_profile_name;
    char            **alpn_protocols;
    size_t           alpn_protocol_count;
    sys_mutex_t      lock;  // must be held when accessing pn_domain
    pn_tls_config_t *pn_domain;
    sys_atomic_t     ref_count;
    qd_log_module_t  log_module;
    bool             authenticate_peer;
    bool             verify_hostname;
    bool             is_listener;
};

DEQ_DECLARE(qd_tls2_domain_t, qd_tls2_domain_list_t);

/**
 * Top-level TLS context
 *
 * Maintains all TLS state associated with an sslProfile record.  Includes the configuration as well as all active TLS
 * domains generated from that sslProfile record.
 */

struct qd_tls_context_t {
    DEQ_LINKS(qd_tls_context_t);
    char                  *ssl_profile_name;
    qd_ssl2_profile_t      config;
    qd_tls2_domain_list_t  domains;
};

DEQ_DECLARE(qd_tls_context_t, qd_tls_context_list_t);
#endif

