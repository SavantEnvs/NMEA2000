// The library's N2kTimer.cpp is built (see build.sh) so that N2kMillis() calls this application-supplied
// clock instead of CLOCK_MONOTONIC. Time then moves only when a harness advances it.
#include "fake_clock.h"

uint32_t g_fake_now_ms = 1000;

extern "C" uint32_t millis() { return g_fake_now_ms; }
