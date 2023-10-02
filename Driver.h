/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/
#pragma once
#include "WdfCommon.h"

EXTERN_C_START
//
// WDFDRIVER Events
//
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD WFPSeeThruEvtUnload;
EVT_WDF_DRIVER_DEVICE_ADD WFPSeeThruEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP WFPSeeThruEvtDriverContextCleanup;
EXTERN_C_END
