#include "qpid/dispatch/eventing.h"
#include "qpid/dispatch/ctools.h"
#include "qpid/dispatch/atomic.h"
#include "qpid/dispatch/compose.h"
#include "qpid/dispatch/router_core.h"
#include "qpid/dispatch/io_module.h"

#include <inttypes.h>

static const char * const my_event_address_prefix = "mc/router.events.";  // suffix router id
static const char *qd_event_type_names[] = {
    "<RESERVED>",  // QD_EVENT_NONE is internal
    "WARNING",
    "ERROR",
    "CRITICAL",
    "TELEMETRY"
};
ENUM_DEFINE(qd_event_type, qd_event_type_names);


static char *my_event_address;
static qdr_watch_handle_t my_address_watch_handle;
static qdr_core_t *router_core;
static char *my_event_address;
static sys_atomic_t consumer_count;

static void _on_my_address_watch(void *, uint32_t, uint32_t, uint32_t, uint32_t);




void qd_event_str(const char *text)
{
    qd_composed_field_t *field = 0;

    if (consumer_count == 0) {
        return;
    }

    fprintf(stdout, "qd_event_str(%s)\n", text);

    field = qd_compose(QD_PERFORMATIVE_PROPERTIES, 0);
    qd_compose_start_list(field);
    qd_compose_insert_null(field);                            // msg-id
    qd_compose_insert_null(field);                            // user-id
    qd_compose_insert_string(field, my_event_address);        // to
    qd_compose_insert_string(field, "EVENT");                 // subject
    qd_compose_end_list(field);

    field = qd_compose(QD_PERFORMATIVE_BODY_AMQP_VALUE, field);
    qd_compose_insert_string(field, text);

    qd_message_t *event = qd_message();
    qd_message_compose_2(event, field, true);
    qdr_send_to2(router_core, event, my_event_address, true, false);

    qd_compose_free(field);
    qd_message_free(event);
}



/**
 * @brief Handler for changes in reachability for this router's event multicast address.
 *        This address is used to send the log records to collectors in the network.
 * 
 * @param context Context for the handler (the core module pointer)
 * @param local_consumers The number of local (on this router) consumers for the address
 * @param in_proc_consumers (unused) The number of in-process consumers for the address
 * @param remote_consumers The number of remote routers with local consumers for the address
 * @param local_producers (unused) The number of local producers for the address
 */
static void _on_my_address_watch(void     *context,
                                 uint32_t  local_consumers,
                                 uint32_t  in_proc_consumers,
                                 uint32_t  remote_consumers,
                                 uint32_t  local_producers)
{
    sys_atomic_set(&consumer_count, local_consumers + remote_consumers);
    fprintf(stdout, "qd_event address watch consumers = %u\n", (unsigned int) local_consumers + remote_consumers);
}


static void _event_init(qdr_core_t *core, void **adaptor_context)
{
    const char *router_id = qd_router_id();
    sys_atomic_init(&consumer_count, 0);
    router_core = core;
    my_event_address = qd_malloc(strlen(my_event_address_prefix) + strlen(router_id) + 1);
    strcpy(my_event_address, my_event_address_prefix);
    strcat(my_event_address, router_id);

    my_address_watch_handle = qdr_core_watch_address(core, my_event_address, 'M', QD_TREATMENT_MULTICAST_ONCE, _on_my_address_watch, 0, core);

    *adaptor_context = (void *)1; // unused

    fprintf(stdout, "event initialized address=%s\n", my_event_address);
}

static void _event_final(void *adaptor_context)
{
    fprintf(stdout, "event finalize\n");
    qdr_core_unwatch_address(router_core, my_address_watch_handle);
    free(my_event_address);
    sys_atomic_destroy(&consumer_count);
}


QDR_CORE_ADAPTOR_DECLARE_ORD("Router Eventer", _event_init, _event_final, 11)
