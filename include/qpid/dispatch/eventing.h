#include "enum.h"
#include "router.h"

typedef enum {
    // Do not reorder or remove! Add new to end and deprecate old values else API will break and users will get very
    // annoyed and come looking for you.
    QD_EVENT_NONE = 0,
    QD_EVENT_WARNING,
    QD_EVENT_ERROR,
    QD_EVENT_CRITICAL,
    QD_EVENT_TELEMETRY,
} qd_event_type_t;
ENUM_DECLARE(qd_event_type);  // defines qd_event_type_name()

void qd_event_str(const char *text);



