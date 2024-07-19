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

#include "qpid/dispatch/tls.h"
#include "private.h"

#include "qpid/dispatch/alloc_pool.h"
#include "qpid/dispatch/error.h"
#include "qpid/dispatch/threading.h"
#include "qpid/dispatch/buffer.h"
#include "entity.h"

#include <proton/tls.h>

#include <inttypes.h>

/*
 * Manages TLS configuration, domain and stream lifecycle
 */


ALLOC_DECLARE(qd_tls2_session_t);
ALLOC_DEFINE(qd_tls2_session_t);

ALLOC_DECLARE(qd_tls2_domain_t);
ALLOC_DEFINE(qd_tls2_domain_t);

ALLOC_DECLARE(qd_tls_context_t);
ALLOC_DEFINE(qd_tls_context_t);


/**
 * Master list of all active TLS context instances. Only accessed by the management thread so no locking necessary.
 */
static qd_tls_context_list_t context_list;


// Internals:
static qd_error_t _read_tls_config(qd_entity_t *entity, qd_ssl2_profile_t *config);
static void _cleanup_tls_config(qd_ssl2_profile_t *config);
static qd_tls_context_t *_find_tls_context(const char *profile_name);
static void _tls_context_free(qd_tls_context_t *ctxt);
static int _tls_domain_update_config(qd_tls2_domain_t *tls_domain, const qd_ssl2_profile_t *config);
static pn_tls_config_t *_allocate_pn_domain(const char *ssl_profile_name, const qd_ssl2_profile_t *config,
                                            bool is_listener, bool verify_hostname, bool authenticate_peer,
                                            const char **alpn_protocols, size_t alpn_protocol_count,
                                            qd_log_module_t log_module);


// TODO: these should be moved somewhere public as they are called from multiple places
extern void qd_server_config_process_password(char **actual_val, char *pw, bool *is_file, bool allow_literal_prefix);
extern void qd_set_password_from_file(const char *password_file, char **password_field);



/* Thread verification We can avoid locking of the context_list IF all the functions that access the list are running on
 * the same thread. Initial configuration file load occurs on main thread, management updates runs via a zero timer.
 */
#define ASSERT_MGMT_THREAD assert(sys_thread_role(0) == SYS_THREAD_MAIN || sys_thread_proactor_mode() == SYS_THREAD_PROACTOR_MODE_TIMER)

void qd_tls2_initialize(void)
{
    DEQ_INIT(context_list);
}


void qd_tls2_finalize(void)
{
    qd_tls_context_t *ctxt = DEQ_HEAD(context_list);
    while (ctxt) {
        DEQ_REMOVE_HEAD(context_list);
        _tls_context_free(ctxt);
        ctxt = DEQ_HEAD(context_list);
    }
}


/**
 * Handle sslProfile record create request from management
 */
QD_EXPORT void *qd_tls_configure_ssl_profile(qd_dispatch_t *qd, qd_entity_t *entity)
{
    ASSERT_MGMT_THREAD;

    qd_error_clear();
    char *name = qd_entity_opt_string(entity, "name", 0);
    if (!name || qd_error_code()) {
        free(name);
        qd_log(LOG_AGENT, QD_LOG_ERROR, "Unable to create sslProfile: %s", qd_error_message());
    }

    qd_tls_context_t *tls_context = new_qd_tls_context_t();
    ZERO(tls_context);
    DEQ_ITEM_INIT(tls_context);
    DEQ_INIT(tls_context->domains);
    tls_context->ssl_profile_name = name;

    if (_read_tls_config(entity, &tls_context->config) != QD_ERROR_NONE) {
        qd_log(LOG_AGENT, QD_LOG_ERROR, "Unable to create sslProfile '%s': %s", name, qd_error_message());
        _tls_context_free(tls_context);
        return 0;
    }

    DEQ_INSERT_TAIL(context_list, tls_context);
    qd_log(LOG_AGENT, QD_LOG_INFO, "Created sslProfile %s", tls_context->ssl_profile_name);
    return tls_context;
}


/**
 * Handle sslProfile record delete request from management.
 */
QD_EXPORT void qd_tls_delete_ssl_profile(qd_dispatch_t *qd, void *impl)
{
    ASSERT_MGMT_THREAD;

    qd_tls_context_t *tls_context = (qd_tls_context_t *) impl;
    assert(tls_context);

    DEQ_REMOVE(context_list, tls_context);

    qd_log(LOG_AGENT, QD_LOG_INFO, "Deleted sslProfile %s", tls_context->ssl_profile_name);

    _tls_context_free(tls_context);
}


/**
 * Handle sslProfile record update request from management.
 */
QD_EXPORT void *qd_tls_update_ssl_profile(qd_dispatch_t *qd, qd_entity_t *entity, void *impl)
{
    ASSERT_MGMT_THREAD;

    qd_tls_context_t  *tls_context = (qd_tls_context_t *) impl;
    qd_ssl2_profile_t  new_config;

    assert(tls_context);
    if (_read_tls_config(entity, &new_config) != QD_ERROR_NONE) {
        qd_log(LOG_AGENT, QD_LOG_ERROR, "Unable to update sslProfile '%s': %s", tls_context->ssl_profile_name, qd_error_message());
        return 0;
    }

    qd_tls2_domain_t *domain = DEQ_HEAD(tls_context->domains);
    while (domain) {
        if (_tls_domain_update_config(domain, &new_config) != 0) {
            // There is a problem with the new configuration. Discard the change and return 0 to force the management
            // operation to fail
            _cleanup_tls_config(&new_config);
            return 0;
        }
        domain = DEQ_NEXT(domain);
    }

    _cleanup_tls_config(&tls_context->config);
    tls_context->config = new_config;
    qd_log(LOG_AGENT, QD_LOG_INFO, "Updated sslProfile %s ", tls_context->ssl_profile_name);
    return impl;
}


qd_tls2_domain_t *qd_tls2_new_domain(const char *name,
                                     const char *ssl_profile_name,
                                     qd_tls_type_t p_type,
                                     qd_tls_domain_mode_t mode,
                                     bool verify_hostname,         // for client mode
                                     bool authenticate_peer,       // for server mode
                                     const char **alpn_protocols,  // for server mode
                                     size_t alpn_protocol_count,
                                     qd_log_module_t log_module)
{
    ASSERT_MGMT_THREAD;  // called from listener/connector create callback

    assert(p_type == QD_TLS_TYPE_PROTON_RAW);  // TBD: AMQP TLS support

    qd_tls_context_t *tls_context = _find_tls_context(ssl_profile_name);
    if (!tls_context) {
        qd_log(log_module, QD_LOG_ERROR, "sslProfile '%s' not found", ssl_profile_name);
        return 0;
    }

    pn_tls_config_t *pn_domain = _allocate_pn_domain(ssl_profile_name, &tls_context->config, mode == QD_TLS_DOMAIN_SERVER_MODE,
                                                     verify_hostname, authenticate_peer, alpn_protocols, alpn_protocol_count,
                                                     log_module);
    if (!pn_domain) {
        qd_log(log_module, QD_LOG_ERROR, "Failed to initialize TLS '%s' with sslProfile '%s'", name, ssl_profile_name);
        return 0;
    }

    qd_tls2_domain_t *tls_domain = new_qd_tls2_domain_t();
    ZERO(tls_domain);
    sys_atomic_init(&tls_domain->ref_count, 1);  // referenced by parent tls_context
    sys_mutex_init(&tls_domain->lock);

    tls_domain->name              = qd_strdup(name);
    tls_domain->ssl_profile_name  = qd_strdup(ssl_profile_name);
    tls_domain->log_module        = log_module;
    tls_domain->authenticate_peer = authenticate_peer;
    tls_domain->verify_hostname   = verify_hostname;
    tls_domain->is_listener       = mode == QD_TLS_DOMAIN_SERVER_MODE;
    if (alpn_protocols && alpn_protocol_count > 0) {
        tls_domain->alpn_protocols = (char **)qd_malloc(sizeof(alpn_protocols[0]) * alpn_protocol_count);
        tls_domain->alpn_protocol_count = alpn_protocol_count;
        for (int i = 0; i < alpn_protocol_count; ++i)
            tls_domain->alpn_protocols[i] = qd_strdup(alpn_protocols[i]);
    }
    tls_domain->pn_domain = pn_domain;

    DEQ_INSERT_TAIL(tls_context->domains, tls_domain);

    qd_log(log_module, QD_LOG_DEBUG, "created TLS domain %s using sslProfile %s", tls_domain->name, ssl_profile_name);

    sys_atomic_inc(&tls_domain->ref_count);  // for caller
    return tls_domain;
}


void qd_tls2_domain_decref(qd_tls2_domain_t *tls_domain)
{
    if (tls_domain) {
        uint32_t rc = sys_atomic_dec(&tls_domain->ref_count);
        assert(rc != 0);  // underflow!
        if (rc == 1) {
            // Last reference: can assume it has already been removed from parent tls_context domain list and no
            // other threads are accessing it
            if (tls_domain->pn_domain)
                pn_tls_config_free(tls_domain->pn_domain);
            free(tls_domain->name);
            free(tls_domain->ssl_profile_name);
            for (int i = 0; i < tls_domain->alpn_protocol_count; ++i) {
                free(tls_domain->alpn_protocols[i]);
            }
            free(tls_domain->alpn_protocols);
            sys_atomic_destroy(&tls_domain->ref_count);
            sys_mutex_free(&tls_domain->lock);
            free_qd_tls2_domain_t(tls_domain);
        }
    }
}


qd_tls2_session_t *qd_tls2_domain_new_session(qd_tls2_domain_t *tls_domain,
                                              uint64_t conn_id,
                                              const char *peer_hostname,
                                              const char **alpn_protocols, size_t alpn_protocol_count,
                                              void *context, qd_tls2_session_on_secure_cb_t *on_secure)
{
    assert(tls_domain);

    qd_tls2_session_t *tls_session = new_qd_tls2_session_t();
    ZERO(tls_session);
    tls_session->conn_id      = conn_id;
    tls_session->user_context = context;
    tls_session->on_secure_cb = on_secure;
    tls_session->log_module   = tls_domain->log_module;
    tls_session->tls_domain   = tls_domain;
    sys_atomic_inc(&tls_domain->ref_count);

    // We need to hold the tls_domain lock while we create the new session.  This prevents management from altering the
    // domain while this thread accesses it, as well as protecting the internal proton TLS domain which is not thread
    // safe.

    sys_mutex_lock(&tls_domain->lock);

    // if this stream needs to override the default ALPN Protocol configuration associated with the domain that also
    // needs to be done whilst holding the lock to prevent other streams from using the wrong ALPN configuration.

    bool restore_alpn = false;
    if (alpn_protocol_count) {
        restore_alpn = true;
        int rc = pn_tls_config_set_alpn_protocols(tls_domain->pn_domain, alpn_protocols, alpn_protocol_count);
        if (rc) {
            sys_mutex_unlock(&tls_domain->lock);

            qd_log(tls_session->log_module, QD_LOG_ERROR,
                   "[C%" PRIu64 "] Failed to configure ALPN settings for new TLS session for sslProfile %s (%d)",
                   conn_id, tls_domain->ssl_profile_name, rc);
            goto error;
        }
    }

    tls_session->pn_tls_session = pn_tls(tls_domain->pn_domain);

    // restore alpn even if the pn_tls() call failed:
    if (restore_alpn) {
        int rc = pn_tls_config_set_alpn_protocols(tls_domain->pn_domain, (const char **) tls_domain->alpn_protocols, tls_domain->alpn_protocol_count);
        if (rc) {
            sys_mutex_unlock(&tls_domain->lock);

            qd_log(tls_session->log_module, QD_LOG_ERROR,
               "[C%" PRIu64 "] Failed to restore ALPN settings for new TLS session for sslProfile %s (%d)",
                   conn_id, tls_domain->ssl_profile_name, rc);
            goto error;
        }
    }

    if (!tls_session->pn_tls_session) {
        sys_mutex_unlock(&tls_domain->lock);

        qd_log(tls_session->log_module, QD_LOG_ERROR,
               "[C%" PRIu64 "] Failed to create new TLS session for sslProfile %s",
               conn_id, tls_domain->ssl_profile_name);
        goto error;
    }

    sys_mutex_unlock(&tls_domain->lock);

    if (peer_hostname) {
        int rc = pn_tls_set_peer_hostname(tls_session->pn_tls_session, peer_hostname);
        if (rc != 0) {
            qd_log(tls_session->log_module, QD_LOG_ERROR,
                   "[C%" PRIu64 "] Failed to configure TLS peer hostname '%s' for sslProfile %s (%d)",
                   conn_id, peer_hostname, tls_domain->ssl_profile_name, rc);
            goto error;
        }
    }

    int rc = pn_tls_start(tls_session->pn_tls_session);
    if (rc != 0) {
        qd_log(tls_session->log_module, QD_LOG_ERROR,
               "[C%" PRIu64 "] Failed to start TLS session for sslProfile %s (%d)",
               conn_id, tls_domain->ssl_profile_name, rc);
        goto error;
    }

    // intitalize tls_has_output to true when the router is acting as the client initiating TLS handshake.
    if (!tls_domain->is_listener) {
        tls_session->tls_has_output = true;
    }

    return tls_session;

error:
    qd_tls2_session_free(tls_session);
    return 0;
}


void qd_tls2_session_free(qd_tls2_session_t *tls_session)
{
    pn_raw_buffer_t buf_desc;

    if (tls_session) {

        if (tls_session->pn_tls_session) {
            pn_tls_stop(tls_session->pn_tls_session);

            while (pn_tls_take_encrypt_output_buffers(tls_session->pn_tls_session, &buf_desc, 1) == 1) {
                qd_buffer_free((qd_buffer_t *) buf_desc.context);
            }
            while (pn_tls_take_encrypt_input_buffers(tls_session->pn_tls_session, &buf_desc, 1) == 1) {
                qd_buffer_free((qd_buffer_t *) buf_desc.context);
            }
            while (pn_tls_take_decrypt_output_buffers(tls_session->pn_tls_session, &buf_desc, 1) == 1) {
                qd_buffer_free((qd_buffer_t *) buf_desc.context);
            }
            while (pn_tls_take_decrypt_input_buffers(tls_session->pn_tls_session, &buf_desc, 1) == 1) {
                qd_buffer_free((qd_buffer_t *) buf_desc.context);
            }

            // Need to lock the pn_domain when releasing the stream since the pn_domain is not thread safe
            sys_mutex_lock(&tls_session->tls_domain->lock);
            if (tls_session->pn_tls_session) {
                pn_tls_free(tls_session->pn_tls_session);
            }
            sys_mutex_unlock(&tls_session->tls_domain->lock);
        }
        qd_tls2_domain_decref(tls_session->tls_domain);
        free_qd_tls2_session_t(tls_session);
    }
}


char *qd_tls2_session_get_alpn_protocol(const qd_tls2_session_t *tls_session)
{
    char       *protocol = 0;
    const char *protocol_name;
    size_t      protocol_name_length;

    assert(tls_session->pn_tls_session);
    if (pn_tls_get_alpn_protocol(tls_session->pn_tls_session, &protocol_name, &protocol_name_length)) {
        protocol = (char *) qd_calloc(protocol_name_length + 1, sizeof(char));
        memmove(protocol, protocol_name, protocol_name_length);
        protocol[protocol_name_length] = '\0';
    }
    return protocol;
}


char *qd_tls2_session_get_protocol_version(const qd_tls2_session_t *tls_session)
{
    char       *version = 0;
    const char *protocol_version;
    size_t      version_len;

    assert(tls_session->pn_tls_session);
    if (pn_tls_get_protocol_version(tls_session->pn_tls_session, &protocol_version, &version_len)) {
        version = (char *) qd_calloc(version_len + 1, sizeof(char));
        memmove(version, protocol_version, version_len);
        version[version_len] = '\0';
    }
    return version;
}

char *qd_tls2_session_get_protocol_ciphers(const qd_tls2_session_t *tls_session)
{
    char       *ciphers = 0;
    const char *protocol_ciphers;
    size_t      ciphers_len;

    assert(tls_session->pn_tls_session);
    if (pn_tls_get_cipher(tls_session->pn_tls_session, &protocol_ciphers, &ciphers_len)) {
        ciphers = (char *) qd_calloc(ciphers_len + 1, sizeof(char));
        memmove(ciphers, protocol_ciphers, ciphers_len);
        ciphers[ciphers_len] = '\0';
    }
    return ciphers;
}


qd_ssl2_profile_t *qd_tls2_read_ssl_profile(const char *ssl_profile_name, qd_ssl2_profile_t *profile)
{
    ASSERT_MGMT_THREAD;

    qd_tls_context_t *tls_context = _find_tls_context(ssl_profile_name);
    if (!tls_context) {
        ZERO(profile);
        return 0;
    }

#define CHECKED_STRDUP(S) (!!(S) ? qd_strdup(S) : 0)
    profile->ssl_ciphers                = CHECKED_STRDUP(tls_context->config.ssl_ciphers);
    profile->ssl_protocols              = CHECKED_STRDUP(tls_context->config.ssl_protocols);
    profile->ssl_password               = CHECKED_STRDUP(tls_context->config.ssl_password);
    profile->ssl_uid_format             = CHECKED_STRDUP(tls_context->config.ssl_uid_format);
    profile->ssl_certificate_file       = CHECKED_STRDUP(tls_context->config.ssl_certificate_file);
    profile->ssl_private_key_file       = CHECKED_STRDUP(tls_context->config.ssl_private_key_file);
    profile->uid_name_mapping_file      = CHECKED_STRDUP(tls_context->config.uid_name_mapping_file);
    profile->ssl_trusted_certificate_db = CHECKED_STRDUP(tls_context->config.ssl_trusted_certificate_db);

    return profile;
}


void qd_tls2_cleanup_ssl_profile(qd_ssl2_profile_t *profile)
{
    if (profile) {
        free(profile->ssl_ciphers);
        free(profile->ssl_protocols);
        free(profile->ssl_trusted_certificate_db);
        free(profile->ssl_certificate_file);
        free(profile->ssl_private_key_file);
        free(profile->ssl_password);
        free(profile->ssl_uid_format);
        free(profile->uid_name_mapping_file);
        ZERO(profile);
    }
}


/**
 * Read the sslProfile configuration record from entity and copy it into config
 */
static qd_error_t _read_tls_config(qd_entity_t *entity, qd_ssl2_profile_t *config)
{
    qd_error_clear();
    ZERO(config);

    config->ssl_ciphers                = qd_entity_opt_string(entity, "ciphers", 0);
    if (qd_error_code()) goto error;
    config->ssl_protocols              = qd_entity_opt_string(entity, "protocols", 0);
    if (qd_error_code()) goto error;
    config->ssl_trusted_certificate_db = qd_entity_opt_string(entity, "caCertFile", 0);
    if (qd_error_code()) goto error;
    config->ssl_certificate_file       = qd_entity_opt_string(entity, "certFile", 0);
    if (qd_error_code()) goto error;
    config->ssl_private_key_file       = qd_entity_opt_string(entity, "privateKeyFile", 0);
    if (qd_error_code()) goto error;
    config->ssl_password               = qd_entity_opt_string(entity, "password", 0);
    if (qd_error_code()) goto error;
    config->ssl_uid_format             = qd_entity_opt_string(entity, "uidFormat", 0);
    if (qd_error_code()) goto error;
    config->uid_name_mapping_file      = qd_entity_opt_string(entity, "uidNameMappingFile", 0);
    if (qd_error_code()) goto error;

    if (config->ssl_password) {
        //
        // Process the password to handle any modifications or lookups needed
        //
        char *actual_pass = 0;
        bool is_file_path = 0;
        qd_server_config_process_password(&actual_pass, config->ssl_password, &is_file_path, true);
        if (qd_error_code()) goto error;

        if (actual_pass) {
            if (is_file_path) {
                qd_set_password_from_file(actual_pass, &config->ssl_password);
                free(actual_pass);
            }
            else {
                free(config->ssl_password);
                config->ssl_password = actual_pass;
            }
        }
    }

    return QD_ERROR_NONE;

error:
    _cleanup_tls_config(config);
    return qd_error_code();
}


/** Release the contents of a configuration instance
 */
static void _cleanup_tls_config(qd_ssl2_profile_t *config)
{
    free(config->ssl_ciphers);
    free(config->ssl_protocols);
    free(config->ssl_trusted_certificate_db);
    free(config->ssl_certificate_file);
    free(config->ssl_private_key_file);
    free(config->ssl_password);
    free(config->ssl_uid_format);
    free(config->uid_name_mapping_file);
    ZERO(config);
}


/** Instantiate a new Proton Raw TLS domain
 */
static pn_tls_config_t *_allocate_pn_domain(const char *ssl_profile_name, const qd_ssl2_profile_t *config,
                                            bool is_listener, bool verify_hostname, bool authenticate_peer,
                                            const char **alpn_protocols, size_t alpn_protocol_count, qd_log_module_t log_module)
{
    pn_tls_config_t *pn_domain = 0;

    do {
        int res = -1;  // assume failure
        pn_domain = pn_tls_config(is_listener ? PN_TLS_MODE_SERVER : PN_TLS_MODE_CLIENT);

        if (!pn_domain) {
            qd_log(log_module, QD_LOG_ERROR, "Failed to create TLS domain from sslProfile '%s'", ssl_profile_name);
            break;
        }

        if (config->ssl_trusted_certificate_db) {
            res = pn_tls_config_set_trusted_certs(pn_domain, config->ssl_trusted_certificate_db);
            if (res != 0) {
                qd_log(log_module, QD_LOG_ERROR, "sslProfile %s: failed to set TLS caCertFile %s: (%d)",
                       ssl_profile_name, config->ssl_trusted_certificate_db, res);
                break;
            }
        }

        // Call pn_tls_config_set_credentials only if "certFile" is provided.
        if (config->ssl_certificate_file) {
            res = pn_tls_config_set_credentials(pn_domain,
                                                config->ssl_certificate_file,
                                                config->ssl_private_key_file,
                                                config->ssl_password);
            if (res != 0) {
                qd_log(log_module, QD_LOG_ERROR,
                       "sslProfile %s: failed to set TLS certificate configuration (certFile) %s: (%d)",
                       ssl_profile_name, config->ssl_certificate_file, res);
                break;
            }
        } else {
            qd_log(log_module, QD_LOG_INFO,
                   "sslProfile %s: did not provide a certFile configuration", ssl_profile_name);
        }

        if (!!config->ssl_ciphers) {
            res = pn_tls_config_set_impl_ciphers(pn_domain, config->ssl_ciphers);
            if (res != 0) {
                qd_log(log_module, QD_LOG_ERROR,
                       "sslProfile %s: failed to configure ciphers %s (%d)", ssl_profile_name, config->ssl_ciphers, res);
                break;
            }
        }

        if (is_listener) {
            if (authenticate_peer) {
                res = pn_tls_config_set_peer_authentication(pn_domain, PN_TLS_VERIFY_PEER, config->ssl_trusted_certificate_db);
            } else {
                res = pn_tls_config_set_peer_authentication(pn_domain, PN_TLS_ANONYMOUS_PEER, 0);
            }
        } else {
            // Connector.
            if (verify_hostname) {
                res = pn_tls_config_set_peer_authentication(pn_domain, PN_TLS_VERIFY_PEER_NAME, config->ssl_trusted_certificate_db);
            } else {
                res = pn_tls_config_set_peer_authentication(pn_domain, PN_TLS_VERIFY_PEER, config->ssl_trusted_certificate_db);
            }
        }

        if (res != 0) {
            qd_log(log_module, QD_LOG_ERROR,
                   "sslProfile %s: failed to configure TLS peer authentication (%d)", ssl_profile_name, res);
            break;
        }

        //
        // Provide an ordered list of application protocols for ALPN by calling pn_tls_config_set_alpn_protocols. In our
        // case, h2 is the only supported protocol. A list of protocols can be found here -
        // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.txt
        //
        if (alpn_protocols) {
            res = pn_tls_config_set_alpn_protocols(pn_domain, alpn_protocols, alpn_protocol_count);
            if (res != 0) {
                qd_log(log_module, QD_LOG_ERROR, "sslProfile %s: failed to configure ALPN protocols (%d)", ssl_profile_name, res);
                break;
            }
        }

        qd_log(log_module, QD_LOG_INFO, "Successfully configured sslProfile %s", ssl_profile_name);
        return pn_domain;

    } while (0);

    // If we get here, the configuration setup failed

    if (pn_domain) {
        pn_tls_config_free(pn_domain);
    }
    return 0;
}


/** Return 0 on success.
 * Note: this function blocks the caller while loading certificate files from the filesystem. It is *SLOW* - assume it
 * will block for at least hundreds of milliseconds!
 */
static int _tls_domain_update_config(qd_tls2_domain_t *tls_domain, const qd_ssl2_profile_t *config)
{
    // Generate a new proton domain using the updated configuration from the parent tls_context and the existing tls_domain.
    // Do this outside of the lock because reloading certs takes a loooong time.
    //
    pn_tls_config_t *pn_domain = _allocate_pn_domain(tls_domain->ssl_profile_name, config, tls_domain->is_listener,
                                                     tls_domain->verify_hostname, tls_domain->authenticate_peer,
                                                     (const char **) tls_domain->alpn_protocols, tls_domain->alpn_protocol_count,
                                                     tls_domain->log_module);
    if (!pn_domain) {
        qd_log(tls_domain->log_module, QD_LOG_ERROR,
               "Failed to update TLS '%s' with updated sslProfile '%s'", tls_domain->name, tls_domain->ssl_profile_name);
        return -1;
    }

    // Pull the old switcheroo on the old pn_domain.  Do this under lock to prevent I/O threads from creating new sessions
    // while we change pointers

    sys_mutex_lock(&tls_domain->lock);
    pn_tls_config_t *old_pn_domain = tls_domain->pn_domain;
    tls_domain->pn_domain = pn_domain;

    // Sadly the pn_tls_config_t is not thread safe so we have to hold the lock when we free it.
    // It maintains a reference count that can be corrupted by multi-threaded access.

    pn_tls_config_free(old_pn_domain);
    sys_mutex_unlock(&tls_domain->lock);

    return 0;
}


/** Find the TLS context associated with the given sslProfile name
 */
static qd_tls_context_t *_find_tls_context(const char *profile_name)
{
    ASSERT_MGMT_THREAD;

    qd_tls_context_t *ctxt = DEQ_HEAD(context_list);
    while (ctxt) {
        if (strcmp(ctxt->ssl_profile_name, profile_name) == 0)
            return ctxt;
        ctxt = DEQ_NEXT(ctxt);
    }
    return 0;
}


/** Free the TLS context. Assumes context is no longer on context_list
 */
static void _tls_context_free(qd_tls_context_t *ctxt)
{
    if (ctxt) {
        qd_tls2_domain_t *tls_domain = DEQ_HEAD(ctxt->domains);
        while (tls_domain) {
            DEQ_REMOVE_HEAD(ctxt->domains);
            qd_tls2_domain_decref(tls_domain);
            tls_domain = DEQ_HEAD(ctxt->domains);
        }
        free(ctxt->ssl_profile_name);
        _cleanup_tls_config(&ctxt->config);
        free_qd_tls_context_t(ctxt);
    }
}

