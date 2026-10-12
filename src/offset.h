#ifndef OFFSET_H
#define OFFSET_H

/*
 * Target selector. The active target profile is chosen at build time via
 * -DTARGET_CONFIG_H="targets/<PROJECT>/target.h" (see the Makefile). Every
 * per-build constant and kernel symbol offset lives in that header.
 */
#include TARGET_CONFIG_H

#endif /* OFFSET_H */
