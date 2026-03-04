#include "lwip/sys.h"
#include <time.h>

u32_t sys_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)(ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL);
}
