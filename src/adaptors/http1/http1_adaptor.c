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

#include "adaptors/adaptor_tls.h"
#include "http1_private.h"

#include <inttypes.h>
#include <stdio.h>

//
// This file contains code for the HTTP/1.x protocol adaptor.  This file
// includes code that is common to both ends of the protocol (e.g. client and
// server processing).  See http1_client.c and http1_server.c for code specific
// to HTTP endpoint processing.
//

/*
  HTTP/1.x <--> AMQP message mapping

  Message Properties Section:

  HTTP Message                  AMQP Message Properties
  ------------                  -----------------------
  Request Method                subject field (request message)
  Response Status code          subject field (response message)

  Application Properties Section:

  HTTP Message                  AMQP Message App Properties Map
  ------------                  -------------------------------
  Message Version               ":version": <version|"1.1" by default>
  Response Reason               ":reason": <string> (response only)
  Request Target                ":path": <string>
  *                             "<lowercase(key)>" <string>

  Notes:
   - Message App Properties Keys that start with ":" are reserved by the
     adaptor for meta-data.
 */

const char *http1_alpn_protocols[HTTP1_NUM_ALPN_PROTOCOLS] = {"http/1.1", "http/1.0"};

ALLOC_DEFINE(qdr_http1_out_data_t);
ALLOC_DEFINE(qdr_http1_connection_t);


qdr_http1_adaptor_t *qdr_http1_adaptor;

void qdr_http1_request_base_cleanup(qdr_http1_request_base_t *hreq)
{
    if (hreq) {
        DEQ_REMOVE(hreq->hconn->requests, hreq);
        h1_codec_request_state_cancel(hreq->lib_rs);
        vflow_end_record(hreq->vflow);
        hreq->vflow = 0;
        free(hreq->response_addr);
        hreq->response_addr = 0;
        free(hreq->site);
        hreq->site = 0;
    }
}


void qdr_http1_connection_free(qdr_http1_connection_t *hconn)
{
    if (hconn) {
        pn_raw_connection_t *rconn = 0;
        qd_timer_t *timer = 0;

        // prevent core from activating this connection while it is being torn
        // down. Also prevent timer callbacks from running. see
        // _core_connection_activate_CT and _do_reconnect in http1_server.c
        //
        sys_mutex_lock(&qdr_http1_adaptor->lock);
        {
            DEQ_REMOVE(qdr_http1_adaptor->connections, hconn);
            timer = hconn->server.reconnect_timer;
            hconn->server.reconnect_timer = 0;
            rconn = hconn->raw_conn;
            hconn->raw_conn = 0;
            if (hconn->server.connector) {
                hconn->server.connector->ctx = 0;
                hconn->server.connector = 0;
            }
            if (hconn->qdr_conn)
                qdr_connection_set_context(hconn->qdr_conn, 0);
            hconn->qdr_conn = 0;
        }
        sys_mutex_unlock(&qdr_http1_adaptor->lock);

        // must free timer outside of lock since callback
        // attempts to take lock:
        qd_timer_free(timer);

        // cleanup outstanding requests
        //
        if (hconn->type == HTTP1_CONN_SERVER)
            qdr_http1_server_conn_cleanup(hconn);
        else
            qdr_http1_client_conn_cleanup(hconn);

        h1_codec_connection_free(hconn->http_conn);
        qd_tls_free(hconn->tls);
        if (rconn) {
            pn_raw_connection_set_context(rconn, 0);
            pn_raw_connection_close(rconn);
            qd_raw_connection_drain_read_write_buffers(rconn);
        }

        sys_atomic_destroy(&hconn->q2_restart);

        free(hconn->cfg.host);
        free(hconn->cfg.port);
        free(hconn->cfg.address);
        free(hconn->cfg.site);
        free(hconn->cfg.host_override);
        free(hconn->cfg.host_port);

        free(hconn->client.client_ip_addr);
        free(hconn->client.reply_to_addr);

        // End the vanflow record for the connection level vanflow.
        vflow_end_record(hconn->vflow);
        free_qdr_http1_connection_t(hconn);
    }
}

static void _free_qdr_http1_out_data(qdr_http1_out_data_t *od)
{
    if (od) {
        qd_iterator_free(od->data_iter);
        if (od->stream_data)
            qd_message_stream_data_release(od->stream_data);
        else
            qd_buffer_list_free_buffers(&od->raw_buffers);
        free_qdr_http1_out_data_t(od);
    }
}

void qdr_http1_out_data_cleanup(qdr_http1_out_data_list_t *out_data)
{
    if (out_data) {
        // expect: all buffers returned from proton!
        // FIXME: not during router shutdown!
        // assert(qdr_http1_out_data_buffers_outstanding(out_data) == 0);
        qdr_http1_out_data_t *od = DEQ_HEAD(*out_data);
        while (od) {
            DEQ_REMOVE_HEAD(*out_data);
            _free_qdr_http1_out_data(od);
            od = DEQ_HEAD(*out_data);
        }
    }
}


// Initiate close of the raw connection.
//
void qdr_http1_close_connection(qdr_http1_connection_t *hconn, const char *error)
{
    if (hconn->closing)
        return;
    hconn->closing = true;

    if (error) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_ERROR, "[C%" PRIu64 "] Connection closing: %s", hconn->conn_id,
               error);
    }

    if (hconn->raw_conn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "] Initiating close of connection",
               hconn->conn_id);
        pn_raw_connection_close(hconn->raw_conn);
    }

    // clean up all connection related stuff on PN_RAW_CONNECTION_DISCONNECTED
    // event
}

//
// Raw Connection Write Buffer Management
//

// Move out_data from the fifo list to the tail of a list of adaptor buffers. Free fifo entries whose data has been
// moved onto the abuf_list. Return the total number of octets added to abuf_list.
//
uint64_t qdr_http1_get_out_buffers(qdr_http1_out_data_list_t *fifo, qd_adaptor_buffer_list_t *abuf_list, size_t limit)
{
    qd_adaptor_buffer_t  *abuf         = 0;
    qdr_http1_out_data_t *od           = 0;
    uint32_t              total_octets = 0;
    while (!DEQ_IS_EMPTY(*fifo) && limit > 0) {
        if (!od)
            od = DEQ_HEAD(*fifo);

        if (!abuf)
            abuf = qd_adaptor_buffer();

        size_t data_octets = qd_iterator_remaining(od->data_iter);
        assert(data_octets > 0);

        unsigned char *abuf_cursor   = qd_adaptor_buffer_cursor(abuf);
        size_t         abuf_capacity = qd_adaptor_buffer_capacity(abuf);
        assert(abuf_capacity > 0);

        size_t copied = qd_iterator_ncopy_octets(od->data_iter, abuf_cursor, MIN(data_octets, abuf_capacity));
        assert(copied > 0);
        total_octets += copied;

        if (qd_iterator_remaining(od->data_iter) == 0) {
            DEQ_REMOVE_HEAD(*fifo);
            _free_qdr_http1_out_data(od);
            od = 0;
        }

        qd_adaptor_buffer_insert(abuf, copied);
        if (qd_adaptor_buffer_capacity(abuf) == 0) {
            DEQ_INSERT_TAIL(*abuf_list, abuf);
            abuf = 0;
            limit -= 1;
        }
    }

    if (abuf) {
        DEQ_INSERT_TAIL(*abuf_list, abuf);
    }
    return total_octets;
}

// The HTTP encoder has a list of buffers to be written to the raw connection.
// Queue it to the outgoing data fifo.
//
void qdr_http1_enqueue_buffer_list(qdr_http1_out_data_list_t *fifo, qd_buffer_list_t *blist, uintmax_t octets)
{
    if (octets) {
        qdr_http1_out_data_t *od = new_qdr_http1_out_data_t();
        ZERO(od);
        od->raw_buffers = *blist;
        od->data_iter = qd_iterator_buffer(DEQ_HEAD(od->raw_buffers), 0, (int)octets, ITER_VIEW_ALL);
        DEQ_INIT(*blist);
        DEQ_INSERT_TAIL(*fifo, od);
    }
}


// The HTTP encoder has a message body data to be written to the raw connection.
// Queue it to the outgoing data fifo.
//
void qdr_http1_enqueue_stream_data(qdr_http1_out_data_list_t *fifo, qd_message_stream_data_t *stream_data)
{
    if (qd_message_stream_data_payload_length(stream_data)) {
        qdr_http1_out_data_t *od = new_qdr_http1_out_data_t();
        ZERO(od);
        od->stream_data = stream_data;
        od->data_iter = qd_message_stream_data_iterator(stream_data);
        DEQ_INSERT_TAIL(*fifo, od);
    } else {
        // empty body-data
        qd_message_stream_data_release(stream_data);
    }
}


// Called during proactor event PN_RAW_CONNECTION_WRITTEN
//
void qdr_http1_free_written_buffers(qdr_http1_connection_t *hconn)
{
    ASSERT_THREAD_MODE(SYS_THREAD_MODE_IO);

    pn_raw_buffer_t pn_buff = {0};

    while (pn_raw_connection_take_written_buffers(hconn->raw_conn, &pn_buff, 1) != 0) {
        qd_adaptor_buffer_t *abuf = (qd_adaptor_buffer_t *) pn_buff.context;
        assert(abuf);
        qd_adaptor_buffer_free(abuf);
    }
}

// Per-message callback to resume receiving after Q2 is unblocked on the
// incoming link (to HTTP app).  This routine runs on another I/O thread so it
// must be thread safe!
//
void qdr_http1_q2_unblocked_handler(const qd_alloc_safe_ptr_t context)
{
    // prevent the hconn from being deleted while running:
    sys_mutex_lock(&qdr_http1_adaptor->lock);

    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*)qd_alloc_deref_safe_ptr(&context);
    if (hconn && hconn->raw_conn) {
        if (sys_atomic_set(&hconn->q2_restart, 1) == 0) {
            pn_raw_connection_wake(hconn->raw_conn);
        }
    }

    sys_mutex_unlock(&qdr_http1_adaptor->lock);
}


//
// Protocol Adaptor Callbacks
//


// Invoked by the core/mgmt thread to wake an I/O thread for the connection.
// Must be thread safe.
//
static void _core_connection_activate_CT(void *context, qdr_connection_t *conn)
{
    bool activated = false;

    sys_mutex_lock(&qdr_http1_adaptor->lock);
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_connection_get_context(conn);
    if (hconn) {
        if (hconn->raw_conn) {
            activated = true;
            if (!hconn->server.reconnecting) {
                pn_raw_connection_wake(hconn->raw_conn);
            }
        } else if (hconn->server.reconnect_timer) {
            assert(hconn->type == HTTP1_CONN_SERVER);
            qd_timer_schedule(hconn->server.reconnect_timer, 0);
            activated = true;
        }
    }
    sys_mutex_unlock(&qdr_http1_adaptor->lock);

    qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "] Connection %s", conn->identity,
           activated ? "activated" : "down, unable to activate");
}


static void _core_link_first_attach(void               *context,
                                    qdr_connection_t   *conn,
                                    qdr_link_t         *link,
                                    qdr_terminus_t     *source,
                                    qdr_terminus_t     *target,
                                    qd_session_class_t  ssn_class)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_connection_get_context(conn);
    if (hconn)
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "] Link first attach", hconn->conn_id);
}


static void _core_link_second_attach(void          *context,
                                     qdr_link_t     *link,
                                     qdr_terminus_t *source,
                                     qdr_terminus_t *target)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (!hconn) return;

    qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link second attach", hconn->conn_id,
           link->identity);

    if (hconn->type == HTTP1_CONN_CLIENT) {
        qdr_http1_client_core_second_attach((qdr_http1_adaptor_t*) context,
                                            hconn, link, source, target);
    }
}


static void _core_link_detach(void *context, qdr_link_t *link, qdr_error_t *error, bool first, bool close)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link detach", hconn->conn_id,
               link->identity);

        qdr_link_set_context(link, 0);
        if (link == hconn->out_link)
            hconn->out_link = 0;
        else
            hconn->in_link = 0;
    }
}


static void _core_link_flow(void *context, qdr_link_t *link, int credit)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link flow (%d)", hconn->conn_id,
               link->identity, credit);
        if (hconn->type == HTTP1_CONN_SERVER)
            qdr_http1_server_core_link_flow((qdr_http1_adaptor_t*) context, hconn, link, credit);
        else
            qdr_http1_client_core_link_flow((qdr_http1_adaptor_t*) context, hconn, link, credit);
    }
}


static void _core_link_offer(void *context, qdr_link_t *link, int delivery_count)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link offer (%d)", hconn->conn_id,
               link->identity, delivery_count);
    }
}


static void _core_link_drained(void *context, qdr_link_t *link)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link drained", hconn->conn_id,
               link->identity);
    }
}


static void _core_link_drain(void *context, qdr_link_t *link, bool mode)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link drain %s", hconn->conn_id,
               link->identity, mode ? "ON" : "OFF");
    }
}


static int _core_link_push(void *context, qdr_link_t *link, int limit)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link push %d", hconn->conn_id,
               link->identity, limit);
        return qdr_link_process_deliveries(qdr_http1_adaptor->core, link, limit);
    }
    return 0;
}


// The I/O thread wants to send this delivery out the link
//
static uint64_t _core_link_deliver(void *context, qdr_link_t *link, qdr_delivery_t *delivery, bool settled)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    uint64_t outcome = PN_RELEASED;

    if (hconn) {
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, DLV_FMT " Core link deliver (%s)", DLV_ARGS(delivery),
               settled ? "settled" : "unsettled");

        if (hconn->type == HTTP1_CONN_SERVER)
            outcome = qdr_http1_server_core_link_deliver(qdr_http1_adaptor, hconn, link, delivery, settled);
        else
            outcome = qdr_http1_client_core_link_deliver(qdr_http1_adaptor, hconn, link, delivery, settled);
    }

    return outcome;
}

static int _core_link_get_credit(void *context, qdr_link_t *link)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_link_get_context(link);
    int credit = 0;
    if (hconn) {
        credit = (link == hconn->in_link) ? hconn->in_link_credit : hconn->out_link_credit;
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, "[C%" PRIu64 "][L%" PRIu64 "] Link get credit (%d)",
               hconn->conn_id, link->identity, credit);
    }

    return credit;
}


// Handle disposition/settlement update for the outstanding incoming HTTP message.
//
static void _core_delivery_update(void *context, qdr_delivery_t *dlv, uint64_t disp, bool settled)
{
    qdr_http1_request_base_t *hreq = (qdr_http1_request_base_t*) qdr_delivery_get_context(dlv);
    if (hreq) {
        qdr_http1_connection_t *hconn = hreq->hconn;
        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG, DLV_FMT " core delivery update disp=0x%" PRIx64 " %s",
               DLV_ARGS(dlv), disp, settled ? "settled" : "unsettled");

        if (hconn->type == HTTP1_CONN_SERVER)
            qdr_http1_server_core_delivery_update(qdr_http1_adaptor, hconn, hreq, dlv, disp, settled);
        else
            qdr_http1_client_core_delivery_update(qdr_http1_adaptor, hconn, hreq, dlv, disp, settled);
    }
}


// This is invoked by management to initiate the connection close process.
// Once the raw conn is closed (DISCONNECT event) we call qdr_connection_closed()
// to finish the close processing
//
static void _core_conn_close(void *context, qdr_connection_t *conn, qdr_error_t *error)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_connection_get_context(conn);
    if (hconn) {
        assert(hconn->qdr_conn == conn);
        char *desc = error ? qdr_error_description(error) : 0;

        qd_log(LOG_HTTP_ADAPTOR, QD_LOG_INFO, "[C%" PRIu64 "] HTTP/1.x %s", hconn->conn_id,
               desc ? desc : "connection closed by management");

        if (hconn->type == HTTP1_CONN_SERVER)
            qdr_http1_server_core_conn_close(qdr_http1_adaptor, hconn);
        else
            qdr_http1_client_core_conn_close(qdr_http1_adaptor, hconn);
        free(desc);
    }
}


static void _core_conn_trace(void *context, qdr_connection_t *conn, bool trace)
{
    qdr_http1_connection_t *hconn = (qdr_http1_connection_t*) qdr_connection_get_context(conn);
    if (hconn) {
        hconn->trace = trace;
        if (trace)
            qd_log(LOG_HTTP_ADAPTOR, QD_LOG_TRACE, "[C%" PRIu64 "] HTTP/1.x trace enabled", hconn->conn_id);
    }
}


//
// Adaptor Setup & Teardown
//


static void qd_http1_adaptor_init(qdr_core_t *core, void **adaptor_context)
{
    qdr_http1_adaptor_t *adaptor = NEW(qdr_http1_adaptor_t);

    ZERO(adaptor);
    adaptor->core = core;
    sys_mutex_init(&adaptor->lock);
    DEQ_INIT(adaptor->listeners);
    DEQ_INIT(adaptor->connectors);
    DEQ_INIT(adaptor->connections);
    adaptor->adaptor = qdr_protocol_adaptor(core,
                                            "http/1.x",
                                            adaptor,             // context
                                            _core_connection_activate_CT,  // core thread only
                                            _core_link_first_attach,
                                            _core_link_second_attach,
                                            _core_link_detach,
                                            _core_link_flow,
                                            _core_link_offer,
                                            _core_link_drained,
                                            _core_link_drain,
                                            _core_link_push,
                                            _core_link_deliver,
                                            _core_link_get_credit,
                                            _core_delivery_update,
                                            _core_conn_close,
                                            _core_conn_trace);
    *adaptor_context = adaptor;
    qdr_http1_adaptor = adaptor;
}


static void qd_http1_adaptor_final(void *adaptor_context)
{
    qd_log(LOG_HTTP_ADAPTOR, QD_LOG_INFO, "Shutting down HTTP/1.x protocol adaptor");

    qdr_http1_adaptor_t *adaptor = (qdr_http1_adaptor_t*) adaptor_context;
    qdr_protocol_adaptor_free(adaptor->core, adaptor->adaptor);

    qd_log(LOG_HTTP_ADAPTOR, QD_LOG_DEBUG,
           "HTTP/1.x %zu connections, %zu listeners, and %zu connectors still active", DEQ_SIZE(adaptor->connections),
           DEQ_SIZE(adaptor->listeners), DEQ_SIZE(adaptor->connectors));

    qdr_http1_connection_t *hconn = DEQ_HEAD(adaptor->connections);
    while (hconn) {
        qdr_http1_connection_free(hconn);
        hconn = DEQ_HEAD(adaptor->connections);
    }
    qd_http_listener_t *li = DEQ_HEAD(adaptor->listeners);
    while (li) {
        DEQ_REMOVE_HEAD(qdr_http1_adaptor->listeners);
        qd_http_listener_decref(li);
        li = DEQ_HEAD(adaptor->listeners);
    }
    qd_http_connector_t *ct = DEQ_HEAD(adaptor->connectors);
    while (ct) {
        DEQ_REMOVE_HEAD(qdr_http1_adaptor->connectors);
        qd_http_connector_decref(ct);
        ct = DEQ_HEAD(adaptor->connectors);
    }

    sys_mutex_free(&adaptor->lock);
    qdr_http1_adaptor =  NULL;

    free(adaptor);
}

// Raw connection I/O loop for unencrypted connections.
//
// Takes full input (read) buffers from the raw connection and appends them to input_data. The total number of input
// octets is returned in input_octets. Calls take_output_cb to retrieve output data from the adaptor and gives it to the
// raw connection (write). Ownership of the buffers on input_data is passed to the caller. This function takes ownership
// of all buffers taken via take_output_cb().
//
void qdr_http1_do_raw_io(uint64_t                         conn_id,
                         pn_raw_connection_t             *raw_conn,
                         qdr_http1_take_output_data_cb_t *take_output_cb,
                         void                            *take_output_context,
                         qd_adaptor_buffer_list_t        *input_data,
                         uint64_t                        *input_octets)
{
    ASSERT_THREAD_MODE(SYS_THREAD_MODE_IO);

    // take any inbound data

    if (input_data) {
        assert(input_octets);
        *input_octets = 0;

        pn_raw_buffer_t pn_buf_desc;
        while (pn_raw_connection_take_read_buffers(raw_conn, &pn_buf_desc, 1) == 1) {
            qd_adaptor_buffer_t *abuf = qd_get_adaptor_buffer_from_pn_raw_buffer(&pn_buf_desc);
            assert(abuf);
            size_t size = qd_adaptor_buffer_size(abuf);
            if (size == 0) {
                qd_adaptor_buffer_free(abuf);
            } else {
                DEQ_INSERT_TAIL(*input_data, abuf);
                *input_octets += size;
            }
        }

        if (*input_octets) {
            qd_log(LOG_HTTP_ADAPTOR, QD_LOG_TRACE,
                   "[C%" PRIu64 "] %" PRIu64 " bytes read from raw connection", conn_id, *input_octets);
        }
    }

    // write any outbound data

    qd_adaptor_buffer_list_t a_bufs = DEQ_EMPTY;
    if (take_output_cb) {
        size_t capacity = pn_raw_connection_write_buffers_capacity(raw_conn);
        if (capacity > 0) {
            int64_t out_octets = take_output_cb(take_output_context, &a_bufs, capacity);

            assert(DEQ_SIZE(a_bufs) <= capacity);
            while (DEQ_HEAD(a_bufs)) {
                pn_raw_buffer_t      pn_buf_desc;
                qd_adaptor_buffer_t *buff = DEQ_HEAD(a_bufs);
                DEQ_REMOVE_HEAD(a_bufs);
                qd_adaptor_buffer_pn_raw_buffer(&pn_buf_desc, buff);
                size_t given = pn_raw_connection_write_buffers(raw_conn, &pn_buf_desc, 1);
                (void) given;
                assert(given == 1);
            }

            if (out_octets == QD_IO_EOS) {
                pn_raw_connection_write_close(raw_conn);
            }

            if (out_octets > 0) {
                qd_log(LOG_HTTP_ADAPTOR, QD_LOG_TRACE,
                       "[C%" PRIu64 "] %" PRId64 " bytes written to the raw connection", conn_id, out_octets);
            }
        }
    }
}

/**
 * Declare the adaptor so that it will self-register on process startup.
 */
QDR_CORE_ADAPTOR_DECLARE("http1.x-adaptor", qd_http1_adaptor_init, qd_http1_adaptor_final)
