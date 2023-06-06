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
 *
 */

// clang-format off
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <proton/event.h>
#include <proton/proactor.h>
#include <proton/raw_connection.h>
#include <proton/listener.h>

#include "adaptors/adaptor_buffer.h"
#include "adaptors/adaptor_common.h"
#include "qpid/dispatch/threading.h"
// clang-format on

#define BOOL2STR(b) ((b) ? "true" : "false")

bool stop       = false;
bool debug_mode = false;  // print debug output

size_t MAX_RX_CAPACITY = 16;
size_t RX_BUFS_LIMIT   = 16;

pn_proactor_t *proactor;
pn_listener_t *listener;

const char *server_address   = "127.0.0.1:8800";
const char *listener_address = "0.0.0.0:8000";

typedef struct tcp_connection_t tcp_connection_t;

// a uni-directional pipe of ordered adaptor buffers containing data to forward
// reader: consumes buffers from HEAD of list
// writer: appends buffers to TAIL of list
//
typedef struct {
    sys_mutex_t              lock;
    int                      ref_count;
    unsigned int             read_closed : 1;
    unsigned int             write_closed : 1;
    qd_adaptor_buffer_list_t out_bufs;
    tcp_connection_t        *reader;
    tcp_connection_t        *writer;
} pipe_t;

struct tcp_connection_t {
    pn_raw_connection_t *raw_conn;
    pipe_t              *read_pipe;
    pipe_t              *write_pipe;
    size_t               pending_rx_bufs;  // given to proton
    uint64_t             rx_octets;
    uint64_t             tx_octets;
};

__attribute__((format(printf, 1, 2))) void debug(const char *format, ...)
{
    va_list args;

    if (!debug_mode)
        return;

    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}

pipe_t *pipe_new(void)
{
    pipe_t *p = (pipe_t *) calloc(1, sizeof(pipe_t));
    assert(p);

    sys_mutex_init(&p->lock);
    DEQ_INIT(p->out_bufs);
    p->ref_count = 1;
    return p;
}

pipe_t *pipe_incref(pipe_t *p)
{
    if (p) {
        sys_mutex_lock(&p->lock);
        assert(p->ref_count > 0);
        p->ref_count += 1;
        sys_mutex_unlock(&p->lock);
    }
    return p;
}

void pipe_decref(pipe_t *p)
{
    if (p) {
        sys_mutex_lock(&p->lock);
        assert(p->ref_count > 0);
        if (--p->ref_count == 0) {
            sys_mutex_unlock(&p->lock);
            qd_adaptor_buffer_list_free_buffers(&p->out_bufs);
            sys_mutex_free(&p->lock);
            free(p);
        } else {
            sys_mutex_unlock(&p->lock);
        }
    }
}

qd_adaptor_buffer_t *pipe_read(pipe_t *p)
{
    qd_adaptor_buffer_t *abuf = 0;

    assert(p);
    sys_mutex_lock(&p->lock);
    abuf = DEQ_HEAD(p->out_bufs);
    if (abuf) {
        DEQ_REMOVE_HEAD(p->out_bufs);
    }
    sys_mutex_unlock(&p->lock);

    return abuf;
}

void pipe_write(pipe_t *p, qd_adaptor_buffer_list_t *bufs)
{
    assert(p);
    assert(bufs);
    sys_mutex_lock(&p->lock);
    if (!p->read_closed) {
        bool wake = DEQ_SIZE(p->out_bufs) == 0;
        DEQ_APPEND(p->out_bufs, *bufs);
        if (wake) {
            // notify reader more data has arrived
            tcp_connection_t *peer = p->reader;
            if (peer && peer->raw_conn) {
                pn_raw_connection_wake(peer->raw_conn);
            }
        }
    } else {
        qd_adaptor_buffer_list_free_buffers(bufs);
    }
    sys_mutex_unlock(&p->lock);
}

// The reader closes its end of the pipe. Further writes will discard
// buffers.
void pipe_close_reader(pipe_t *p)
{
    assert(p);
    sys_mutex_lock(&p->lock);
    p->reader = 0;
    if (!p->read_closed) {
        debug("Closing read end of pipe %p\n", (void *) p);
        p->read_closed = 1;
        qd_adaptor_buffer_list_free_buffers(&p->out_bufs);

        // notify the writer so it can close its incoming socket
        if (p->writer && p->writer->raw_conn) {
            pn_raw_connection_wake(p->writer->raw_conn);
        }
    }
    sys_mutex_unlock(&p->lock);
}

// The writer closes its end of the pipe. Once all outstanding buffers are read no further buffers will become
// available.
void pipe_close_writer(pipe_t *p)
{
    assert(p);
    sys_mutex_lock(&p->lock);
    p->writer = 0;
    if (!p->write_closed) {
        p->write_closed = 1;
        if (p->reader && p->reader->raw_conn) {
            pn_raw_connection_wake(p->reader->raw_conn);
        }
    }
    sys_mutex_unlock(&p->lock);
}

// Return true if the pipe is closed for reading. This means the writer has closed its end of the pipe and there are no
// more buffers available.
bool pipe_read_closed(pipe_t *p)
{
    assert(p);
    sys_mutex_lock(&p->lock);
    bool is_closed = p->write_closed && (DEQ_SIZE(p->out_bufs) == 0);
    sys_mutex_unlock(&p->lock);
    return is_closed;
}

// Return true if the pipe is closed for writing. This means the reader is no longer present.
bool pipe_write_closed(pipe_t *p)
{
    assert(p);
    sys_mutex_lock(&p->lock);
    bool is_closed = p->read_closed;
    sys_mutex_unlock(&p->lock);
    return is_closed;
}

tcp_connection_t *new_connection(pn_raw_connection_t *raw_conn)
{
    tcp_connection_t *tcp_conn = (tcp_connection_t *) calloc(1, sizeof(tcp_connection_t));
    assert(tcp_conn);
    assert(raw_conn);

    tcp_conn->raw_conn = raw_conn;
    pn_raw_connection_set_context(raw_conn, tcp_conn);
    return tcp_conn;
}

void free_connection(tcp_connection_t *tcp_conn)
{
    if (tcp_conn) {
        if (tcp_conn->read_pipe) {
            pipe_close_reader(tcp_conn->read_pipe);
            pipe_decref(tcp_conn->read_pipe);
        }

        if (tcp_conn->write_pipe) {
            pipe_close_writer(tcp_conn->write_pipe);
            pipe_decref(tcp_conn->write_pipe);
        }

        if (tcp_conn->raw_conn) {
            pn_raw_connection_set_context(tcp_conn->raw_conn, 0);
            pn_raw_connection_close(tcp_conn->raw_conn);
        }

        printf("Conn closed: %" PRIu64 " octets read, %" PRIu64 " octets written\n", tcp_conn->rx_octets,
               tcp_conn->tx_octets);
        free(tcp_conn);
    }
}

static void signal_handler(int signum)
{
    signal(signum, SIG_IGN);
    stop = true;
    if (proactor)
        pn_proactor_interrupt(proactor);
}

static void listener_event_handler(pn_event_t *event)
{
    const pn_event_type_t type = pn_event_type(event);
    switch (type) {
        case PN_LISTENER_OPEN: {
            break;
        }
        case PN_LISTENER_CLOSE: {
            break;
        }
        case PN_LISTENER_ACCEPT: {
            tcp_connection_t *client = new_connection(pn_raw_connection());
            tcp_connection_t *server = new_connection(pn_raw_connection());

            // create two pipes, one for each flow

            client->read_pipe  = pipe_new();
            server->write_pipe = pipe_incref(client->read_pipe);

            server->read_pipe  = pipe_new();
            client->write_pipe = pipe_incref(server->read_pipe);

            // this will spawn the server and client connection threads:
            pn_proactor_raw_connect(proactor, server->raw_conn, server_address);
            pn_listener_raw_accept(pn_event_listener(event), client->raw_conn);

            // note: now that the connection threads are running, the pipes can only be accessed while holding their
            // mutex lock!
            break;
        }
        default:
            assert(false);
            break;
    }
}

// Attempt to move buffers from the read pipe to the raw connection
//
static void do_output(tcp_connection_t *tcp_conn)
{
    assert(tcp_conn && tcp_conn->read_pipe);

    size_t capacity = pn_raw_connection_write_buffers_capacity(tcp_conn->raw_conn);
    qd_adaptor_buffer_t *abuf     = 0;

    while (capacity-- && (abuf = pipe_read(tcp_conn->read_pipe)) != 0) {
        pn_raw_buffer_t desc;
        tcp_conn->tx_octets += qd_adaptor_buffer_size(abuf);
        qd_adaptor_buffer_pn_raw_buffer(&desc, abuf);
        size_t given = pn_raw_connection_write_buffers(tcp_conn->raw_conn, &desc, 1);
        (void) given;
        assert(given == 1);
    }
}

// Attempt to move buffers from the raw connection into the write pipe
//
static void do_input(tcp_connection_t *tcp_conn)
{
    pn_raw_buffer_t          desc  = {0};
    qd_adaptor_buffer_list_t blist = DEQ_EMPTY;
    while (pn_raw_connection_take_read_buffers(tcp_conn->raw_conn, &desc, 1) == 1) {
        assert(tcp_conn->pending_rx_bufs > 0);
        tcp_conn->pending_rx_bufs -= 1;
        qd_adaptor_buffer_t *abuf  = qd_get_adaptor_buffer_from_pn_raw_buffer(&desc);
        size_t               bsize = qd_adaptor_buffer_size(abuf);
        if (bsize) {
            tcp_conn->rx_octets += bsize;
            DEQ_INSERT_TAIL(blist, abuf);
        } else {
            qd_adaptor_buffer_free(abuf);
        }
    }
    if (!DEQ_IS_EMPTY(blist)) {
        pipe_write(tcp_conn->write_pipe, &blist);
    }
}

/* Process each connection event posted by the proactor
 */
static void connection_event_handler(pn_event_t *event)
{
    const pn_event_type_t type = pn_event_type(event);

    pn_raw_connection_t *raw_conn = pn_event_raw_connection(event);
    if (!raw_conn) {
        debug("conn event MISSING RAW CONN!\n");
        return;
    }

    tcp_connection_t *tcp_conn = pn_raw_connection_get_context(raw_conn);
    if (!tcp_conn) {
        debug("conn event MISSING TCP CONN!\n");
        return;
    }

    switch (type) {
        case PN_RAW_CONNECTION_CONNECTED: {
            // now that the raw_conn is active it is safe to get wake events from our pipe peers. Enable wakeups by
            // setting our backpointer in the pipes

            assert(tcp_conn->read_pipe);
            sys_mutex_lock(&tcp_conn->read_pipe->lock);
            tcp_conn->read_pipe->reader = tcp_conn;
            sys_mutex_unlock(&tcp_conn->read_pipe->lock);

            assert(tcp_conn->write_pipe);
            sys_mutex_lock(&tcp_conn->write_pipe->lock);
            tcp_conn->write_pipe->writer = tcp_conn;
            sys_mutex_unlock(&tcp_conn->write_pipe->lock);
            break;
        }
        case PN_RAW_CONNECTION_DISCONNECTED: {
            // drop our pipe references and delete the connection
            free_connection(tcp_conn);
            tcp_conn = 0;
            return;  // raw connection no longer valid
        }
        case PN_RAW_CONNECTION_WAKE: {
            // The pipe peer will wake this connection for one of 3 reasons:
            // - New buffers have become available to read
            // - The peer has closed its read end of the pipe (no more writes allowed)
            // - The peer has closed its write end of the pipe.
            do_output(tcp_conn);  // write/drain pending readable buffers
            if (pipe_read_closed(tcp_conn->read_pipe)) {
                pn_raw_connection_write_close(tcp_conn->raw_conn);
            }
            if (pipe_write_closed(tcp_conn->write_pipe)) {
                pn_raw_connection_read_close(tcp_conn->raw_conn);
            }
            break;
        }
        case PN_RAW_CONNECTION_NEED_READ_BUFFERS: {
            // check if we are not at the read buff limit

            size_t capacity = pn_raw_connection_read_buffers_capacity(tcp_conn->raw_conn);
            capacity        = MIN(capacity, (RX_BUFS_LIMIT - tcp_conn->pending_rx_bufs));
            while (capacity--) {
                qd_adaptor_buffer_t *abuf = qd_adaptor_buffer();
                pn_raw_buffer_t      desc = {
                         .bytes    = (char *) qd_adaptor_buffer_base(abuf),
                         .capacity = qd_adaptor_buffer_capacity(abuf),
                         .context  = (uintptr_t) abuf,
                };

                pn_raw_connection_give_read_buffers(tcp_conn->raw_conn, &desc, 1);
                tcp_conn->pending_rx_bufs += 1;
            }
            assert(tcp_conn->pending_rx_bufs <= RX_BUFS_LIMIT);
            debug("Pending RX BUFS: %zu\n", tcp_conn->pending_rx_bufs);
            break;
        }

        case PN_RAW_CONNECTION_READ: {
            do_input(tcp_conn);
            break;
        }

        case PN_RAW_CONNECTION_NEED_WRITE_BUFFERS: {
            do_output(tcp_conn);
            // check if all output is complete
            if (pipe_read_closed(tcp_conn->read_pipe)) {
                pn_raw_connection_write_close(tcp_conn->raw_conn);
            }
            break;
        }

        case PN_RAW_CONNECTION_WRITTEN:
            qd_raw_connection_drain_write_buffers(tcp_conn->raw_conn);
            break;

        case PN_RAW_CONNECTION_CLOSED_WRITE:
            // Can no longer write outgoing data, so close the read end of the pipe
            qd_raw_connection_drain_write_buffers(tcp_conn->raw_conn);
            if (tcp_conn->read_pipe) {
                pipe_close_reader(tcp_conn->read_pipe);
            }
            break;

        case PN_RAW_CONNECTION_CLOSED_READ:
            do_input(tcp_conn);  // drain pending read buffers, discard empty ones
            if (tcp_conn->write_pipe) {
                pipe_close_writer(tcp_conn->write_pipe);
            }
            break;

        case PN_RAW_CONNECTION_DRAIN_BUFFERS:
            qd_raw_connection_drain_write_buffers(tcp_conn->raw_conn);
            tcp_conn->pending_rx_bufs -= qd_raw_connection_drain_read_buffers(tcp_conn->raw_conn);
            assert(tcp_conn->pending_rx_bufs == 0);
            break;

        default:
            break;
    }
}

static bool event_handler(pn_event_t *event)
{
    const pn_event_type_t type = pn_event_type(event);
    debug("new proactor event=%s\n", pn_event_type_name(type));

    if (type == PN_PROACTOR_INTERRUPT) {
        debug("Exiting tcp-proxy...\n");
        return true;  // exit proxy
    }

    if (pn_event_listener(event)) {
        listener_event_handler(event);
    } else if (pn_event_raw_connection(event)) {
        connection_event_handler(event);
    } else {
        debug("Ignoring proactor event %s\n", pn_event_type_name(type));
    }
    return false;
}

static void usage(void)
{
    printf("Usage: tcp-proxy <options>\n");
    printf("-c \tThe address:port of the server to connect to [%s]\n", server_address);
    printf("-l \tThe address:port to listen on for incoming client connections [%s]\n", listener_address);
    printf("-n \tMaximum size of connection RX buffer pool [%zu]\n", RX_BUFS_LIMIT);
    printf("-D \tPrint debug info [off]\n");
    exit(1);
}

int main(int argc, char **argv)
{
    /* command line options */
    opterr = 0;
    int c;
    while ((c = getopt(argc, argv, "c:l:n:Dh")) != -1) {
        switch (c) {
            case 'h':
                usage();
                break;
            case 'c':
                server_address = optarg;
                break;
            case 'l':
                listener_address = optarg;
                break;
            case 'n':
                if (sscanf(optarg, "%zu", &RX_BUFS_LIMIT) != 1)
                    usage();
                break;
            case 'D':
                debug_mode = true;
                break;

            default:
                usage();
                break;
        }
    }

    signal(SIGQUIT, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("tcp-proxy active: %zu RX Bufs, server: %s listening on %s\n", RX_BUFS_LIMIT, server_address,
           listener_address);

    proactor = pn_proactor();
    // pn_proactor_addr(proactor_address, sizeof(proactor_address), host, port);
    // pn_proactor_connect2(proactor, pn_conn, 0, proactor_address);

    // create the listener
    listener = pn_listener();
    pn_proactor_listen(proactor, listener, listener_address, 32);

    bool done = false;
    while (!done) {
        pn_event_batch_t *events = pn_proactor_wait(proactor);
        pn_event_t *event = pn_event_batch_next(events);
        while (event) {
            done = event_handler(event);
            if (done)
                break;

            event = pn_event_batch_next(events);
        }
        pn_proactor_done(proactor, events);
    }

    pn_proactor_free(proactor);
    return 0;
}
