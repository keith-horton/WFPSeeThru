/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver and user applications.

Environment:

    user and kernel

--*/
#pragma once
#include <initguid.h>

//
// Define an Interface Guid so that apps can find the device and talk to it.
//
// {75ca7f13-45d8-4c24-8b35-4ebf7db0791f}
DEFINE_GUID(
    GUID_DEVINTERFACE_WFPSeeThru,
    0x75ca7f13, 0x45d8, 0x4c24, 0x8b, 0x35, 0x4e, 0xbf, 0x7d, 0xb0, 0x79, 0x1f);
