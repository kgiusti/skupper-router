#ifndef __tls_h__
#define __tls_h__ 1
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
 * Management of TLS configuration and state
 */


#include "qpid/dispatch/log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


typedef struct qd_tls2_domain_t  qd_tls2_domain_t;   // SSL configuration domain
typedef struct qd_tls2_session_t qd_tls2_session_t;  // per connection SSL state
typedef struct qd_ssl2_profile_t qd_ssl2_profile_t;  // sslProfile configuration record

// Proton has two different SSL/TLS implementations: one for AMQP and a buffer-based one for use with Raw Connections:
typedef enum {
    QD_TLS_TYPE_NONE = 0,     // unset
    QD_TLS_TYPE_PROTON_AMQP,  // for use with AMQP transport
    QD_TLS_TYPE_PROTON_RAW,   // use raw connection/qd_buffer_t interface
} qd_tls_type_t;

typedef enum {
    QD_TLS_DOMAIN_MODE_NONE = 0,  // unset
    QD_TLS_DOMAIN_SERVER_MODE,    // Operate as an SSL server (i.e. listener socket)
    QD_TLS_DOMAIN_CLIENT_MODE,    // Operate as an SSL client (i.e. outgoing connections)
} qd_tls_domain_mode_t;

// sslProfile configuration record
struct qd_ssl2_profile_t {
    char *ssl_ciphers;
    char *ssl_protocols;
    char *ssl_trusted_certificate_db;
    char *ssl_certificate_file;
    char *ssl_private_key_file;
    char *ssl_password;
    char *ssl_uid_format;
    char *uid_name_mapping_file;
};

void qd_tls2_initialize(void);
void qd_tls2_finalize(void);

qd_tls2_domain_t *qd_tls2_new_domain(const char *name,
                                     const char *ssl_profile_name,
                                     qd_tls_type_t p_type,
                                     qd_tls_domain_mode_t mode,
                                     bool verify_hostname,         // for client mode
                                     bool authenticate_peer,       // for server mode
                                     const char **alpn_protocols,  // for server mode
                                     size_t alpn_protocol_count,
                                     qd_log_module_t log_module);
void qd_tls2_domain_decref(qd_tls2_domain_t *domain);

typedef void qd_tls2_session_on_secure_cb_t(qd_tls2_session_t *session, void *context);
qd_tls2_session_t *qd_tls2_domain_new_session(qd_tls2_domain_t *domain,
                                              uint64_t conn_id,
                                              const char *peer_hostname,
                                              // override default ALPN config for this session
                                              const char **alpn_protocols, size_t alpn_protocol_count,
                                              void *context, qd_tls2_session_on_secure_cb_t *on_secure);

void qd_tls2_session_free(qd_tls2_session_t *session);


// Get the negotiated ALPN value from the session. Returned string buffer must be free()d by caller. Return 0 if no ALPN
// (yet) negotiated.
char *qd_tls2_session_get_alpn_protocol(const qd_tls2_session_t *session);

// Get the version of TLS/SSL in use by the session. Returned string buffer must be free()d by caller. Return 0 if
// version not known.
char *qd_tls2_session_get_protocol_version(const qd_tls2_session_t *session);

// Get the cipher string for the ciphers in use by the session. Returned string buffer must be free()d by caller. Return
// 0 if ciphers not known.
char *qd_tls2_session_get_protocol_ciphers(const qd_tls2_session_t *session);

// Fill out the given *profile with the configuration from the named sslProfile record. Return a pointer to the profile
// parameter on success else 0. Use qd_tls2_cleanup_ssl_profile() release resources in use by *profile when done.
qd_ssl2_profile_t *qd_tls2_read_ssl_profile(const char *ssl_profile_name, qd_ssl2_profile_t *profile);

// Release any resources allocated by qd_tls2_get_ssl_profile() and reset the *profile.  Note this only releases
// internal resources associated with the profile, the memory pointed to by *profile is not modified.
void qd_tls2_cleanup_ssl_profile(qd_ssl2_profile_t *profile);

#endif

