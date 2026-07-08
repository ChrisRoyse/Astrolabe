#ifndef ASTROLABE_ASTRO_FFI_H
#define ASTROLABE_ASTRO_FFI_H

#if !defined(CBM_API)
#if defined(_WIN32)
#define CBM_API __declspec(dllexport)
#else
#define CBM_API __attribute__((visibility("default")))
#endif
#endif

#include "cbm.h"
#include "discover/discover.h"
#include "git/git_context.h"
#include "mcp/mcp.h"
#include "pipeline/pipeline.h"
#include "store/store.h"

#endif /* ASTROLABE_ASTRO_FFI_H */
