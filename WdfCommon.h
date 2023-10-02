/*++

Module Name:

    WdfCommon.h

Abstract:

    This file contains the many headers that are required for a WDF driver.
    This allows all headers to "include what you need" so all cpp files only need to include headers for types they require

Environment:

    Kernel-mode Driver Framework

--*/
#pragma once

#include <ntddk.h>
#include <ntdef.h>
#include <Ntstrsafe.h>
#include <wdm.h>
#include <wdf.h>
#include <wdfdriver.h>
#include <wdfio.h>
#include <wdfobject.h>
#include <wdfglobals.h>
#include <wdfobject.h>
