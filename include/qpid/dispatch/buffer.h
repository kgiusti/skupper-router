#ifndef __dispatch_buffer_h__
#define __dispatch_buffer_h__ 1
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

/** @file
 * Buffer chains.
 * @internal
 * @defgroup buffer buffer
 * @{
 */

#include "qpid/dispatch/atomic.h"
#include "qpid/dispatch/ctools.h"

typedef struct qd_buffer_t qd_buffer_t;

DEQ_DECLARE(qd_buffer_t, qd_buffer_list_t);

#define QD_BUFFER_DEFAULT_SIZE 512
extern size_t BUFFER_SIZE;

/** A raw byte buffer
 * Memory for the payload is appended to this structure when the qd_buffer_t is allocated. Payload data can be accessed
 * starting at the first octet past this structure.
 *
 * The bfanout (buffer fanout) field is set to the number of outgoing links this buffer will be sent out. For unicast
 * messages this will be 1, but for multicast and local subscribers it may be > 1. Each time this buffer is completely
 * sent out a link the bfanout count is decremented and the buffer can be freed once bfanout becomes zero. Note well
 * that since multiple links may be processed concurrently on different I/O threads the bfanout count MUST be protected
 * by the message content lock. See message.c for details.
 */
struct qd_buffer_t {
    DEQ_LINKS(qd_buffer_t);
    unsigned int size;     ///< Size of data content
    uint32_t     bfanout;
};

/**
 * Create a buffer with capacity set to the value of BUFFER_SIZE, and data
 * content size of 0 bytes.
 */
qd_buffer_t *qd_buffer(void);

/**
 * Free a buffer
 * @param buf A pointer to an allocated buffer
 */
void qd_buffer_free(qd_buffer_t *buf);

/**
 * Return a pointer to the start of the buffer.
 * @param buf A pointer to an allocated buffer
 * @return A pointer to the first octet in the buffer
 */
static inline unsigned char *qd_buffer_base(const qd_buffer_t *buf)
{
    return (unsigned char*) &buf[1];
}

/**
 * Return a pointer to the first unused byte in the buffer.
 * @param buf A pointer to an allocated buffer
 * @return A pointer to the first free octet in the buffer, the insert point for new data.
 */
static inline unsigned char *qd_buffer_cursor(const qd_buffer_t *buf)
{
    return ((unsigned char*) &buf[1]) + buf->size;
}

/**
 * Return remaining capacity at end of buffer.
 * @param buf A pointer to an allocated buffer
 * @return The number of octets in the buffer's free space, how many octets may be inserted.
 */
static inline size_t qd_buffer_capacity(const qd_buffer_t *buf)
{
    return BUFFER_SIZE - buf->size;
}

/**
 * Return the size of the buffers data content.
 * @param buf A pointer to an allocated buffer
 * @return The number of octets of data in the buffer
 */
static inline size_t qd_buffer_size(const qd_buffer_t *buf)
{
    return buf->size;
}

/**
 * Notify the buffer that octets have been inserted at the buffer's cursor.  This will advance the
 * cursor by len octets.
 *
 * @param buf A pointer to an allocated buffer
 * @param len The number of octets that have been appended to the buffer
 */
static inline void qd_buffer_insert(qd_buffer_t *buf, size_t len)
{
    buf->size += len;
    assert(buf->size <= BUFFER_SIZE);
}

/**
 * Create a new buffer list by cloning an existing one.
 *
 * @param dst A pointer to a list to contain the new buffers
 * @param src A pointer to an existing buffer list
 * @return the number of bytes of data in the new chain
 */
unsigned int qd_buffer_list_clone(qd_buffer_list_t *dst, const qd_buffer_list_t *src);

/**
 * Free all the buffers contained in a buffer list
 *
 * @param list A pointer to a list containing buffers.  On return this list
 * will be set to an empty list.
 */
void qd_buffer_list_free_buffers(qd_buffer_list_t *list);

/**
 * Return the total number of data bytes in a buffer list
 *
 * @param list A pointer to a list containing buffers.
 * @return total number of bytes of data in the buffer list
 */
unsigned int qd_buffer_list_length(const qd_buffer_list_t *list);

/**
 * Advance the buffer by len. Does not manipulate the contents of the buffer
 * @param buf A pointer to an allocated buffer
 * @param len The number of octets that by which the buffer should be advanced.
 */
static inline unsigned char *qd_buffer_at(const qd_buffer_t *buf, size_t len)
{
    assert(len <= BUFFER_SIZE);
    return ((unsigned char*) &buf[1]) + len;
}


/**
 * qd_buffer_list_append
 *
 * Append new data to a buffer list using freespace efficiently and adding new buffers when necessary.
 *
 * @param buflist Pointer to a buffer list that will possibly be changed by adding new buffers
 * @param data Pointer to raw binary data to be added to the buffer list
 * @param len The number of bytes of data to append
 */
void qd_buffer_list_append(qd_buffer_list_t *buflist, const uint8_t *data, size_t len);


///@}

#endif
