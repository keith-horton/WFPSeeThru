/*++

Module Name:

    Trace.h

Abstract:

    Header file for the debug tracing related function definitions and macros.

Environment:

    Kernel mode

--*/
#pragma once
#include <wdm.h>
#include <winmeta.h>
#include <TraceLoggingProvider.h>

TRACELOGGING_DECLARE_PROVIDER(g_routePolicyLoggingProvider);

#define TraceInfoMessage(functionName, message) \
    TraceLoggingWrite( \
        g_routePolicyLoggingProvider, \
        functionName, \
        TraceLoggingLevel(WINEVENT_LEVEL_INFO), \
        TraceLoggingValue(message, "message")); \
    DbgPrint("%s : %s\n", functionName, message) \


#define TraceErrorMessage(status, functionName, message) \
    TraceLoggingWrite( \
        g_routePolicyLoggingProvider, \
        functionName, \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR), \
        TraceLoggingValue(message, "message"), \
        TraceLoggingNTStatus(status, "status")); \
    DbgPrint("%s : %s returned 0x%x\n", functionName, message, status) \

// wil does not have a RETURN_IF_NTSTATUS_FAILED macro for Kernel
// building effectively the same here
#define RETURN_IF_NTSTATUS_FAILED(status, functionName, message) \
    if (!NT_SUCCESS((status))) \
    { \
        TraceErrorMessage(status, functionName, message); \
        return status;\
    } \
