#pragma once
#include <sys/types.h>

// Foreground privileged transport supervisor. The caller supplies one bounded
// JSON request on stdin, then keeps the lease alive through the same pipe.
int tuntomProcess(uid_t owner);
int tuntomService(uid_t owner);
