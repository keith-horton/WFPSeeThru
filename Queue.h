/*++

Module Name:

    queue.h

Abstract:

    This file contains the queue definitions.

Environment:

    Kernel-mode Driver Framework

--*/
#pragma once
#include "WdfCommon.h"

EXTERN_C_START
//
// This is the context that can be placed per queue
// and would contain per queue information.
//
struct QUEUE_CONTEXT
{
    ULONG PrivateDeviceData{}; // just a placeholder
};

// Below unwinds this macro declared in wdfobject.h
// - necessary so we can add appropriate casts to compile with C++
// WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_CONTEXT, QueueGetContext)

typedef QUEUE_CONTEXT* WDF_POINTER_TYPE_QUEUE_CONTEXT;

inline
__declspec(allocate(".data"))
__declspec(selectany)
extern
const WDF_OBJECT_CONTEXT_TYPE_INFO WDF_QUEUE_CONTEXT_TYPE_INFO
{
    .Size = static_cast<ULONG>(sizeof(WDF_OBJECT_CONTEXT_TYPE_INFO)),
    .ContextName = const_cast<PCHAR>("QUEUE_CONTEXT"),
    .ContextSize = sizeof(QUEUE_CONTEXT),
    .UniqueType = &WDF_QUEUE_CONTEXT_TYPE_INFO,
    .EvtDriverGetUniqueContextType = nullptr
};

WDF_POINTER_TYPE_QUEUE_CONTEXT inline QueueGetContext(WDFOBJECT Handle)
{
    return static_cast<WDF_POINTER_TYPE_QUEUE_CONTEXT>(
        WdfObjectGetTypedContextWorker(Handle, (&WDF_QUEUE_CONTEXT_TYPE_INFO)->UniqueType));
}

NTSTATUS WFPSeeThruQueueInitialize(WDFDEVICE Device);

//
// Events from the IoQueue object
//
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL WFPSeeThruEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP WFPSeeThruEvtIoStop;

EXTERN_C_END