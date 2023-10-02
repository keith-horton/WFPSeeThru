/*++

Module Name:

    device.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once
#include "WdfCommon.h"

EXTERN_C_START

//
// The device context performs the same job as
// a WDM device extension in the driver frameworks
//
struct DEVICE_CONTEXT
{
    ULONG PrivateDeviceData;  // just a placeholder
};

//
// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
// Below unwinds this macro declared in wdfobject.h
// - necessary so we can add appropriate casts to compile with C++
// WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

typedef DEVICE_CONTEXT* WDF_POINTER_TYPE_DEVICE_CONTEXT;

//
// the underscore is required in the name for the macro WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE to resolve
//
inline
__declspec(allocate(".data"))
__declspec(selectany)
extern
const WDF_OBJECT_CONTEXT_TYPE_INFO _WDF_DEVICE_CONTEXT_TYPE_INFO  // NOLINT(bugprone-reserved-identifier, clang-diagnostic-reserved-identifier)
{
    .Size = static_cast<ULONG>(sizeof(WDF_OBJECT_CONTEXT_TYPE_INFO)),
    .ContextName = const_cast<PCHAR>("DEVICE_CONTEXT"),
    .ContextSize = sizeof(DEVICE_CONTEXT),
    .UniqueType = &_WDF_DEVICE_CONTEXT_TYPE_INFO,
    .EvtDriverGetUniqueContextType = nullptr
};

WDF_POINTER_TYPE_DEVICE_CONTEXT inline DeviceGetContext(WDFOBJECT Handle)
{
    return static_cast<WDF_POINTER_TYPE_DEVICE_CONTEXT>(
        WdfObjectGetTypedContextWorker(Handle, (&_WDF_DEVICE_CONTEXT_TYPE_INFO)->UniqueType));
}

//
// Function to initialize the device and its callbacks
//
NTSTATUS WFPSeeThruCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit);

EXTERN_C_END
