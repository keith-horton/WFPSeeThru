/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.
    Install this driver manually: devcon install WFPSeeThru.inf Root\WFPSeeThru
    If failed, check %windir%\inf\setupapi.dev.log

Environment:

    Kernel-mode Driver Framework

--*/

// Created following the guidance from:
// https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/writing-a-kmdf-driver-based-on-a-template

#include "Device.h"
#include "Driver.h"
#include "Trace.h"
#include <wil/resource.h>

// {C82052B6-2B84-4037-A82F-B8CF852122C2}
TRACELOGGING_DEFINE_PROVIDER(
    g_routePolicyLoggingProvider,
    "WFP.SeeThru.Driver",
    (0xc82052b6, 0x2b84, 0x4037, 0xa8, 0x2f, 0xb8, 0xcf, 0x85, 0x21, 0x22, 0xc2));

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, WFPSeeThruEvtUnload)
#pragma alloc_text (PAGE, WFPSeeThruEvtDeviceAdd)
#pragma alloc_text (PAGE, WFPSeeThruEvtDriverContextCleanup)
#endif

DECLARE_CONST_UNICODE_STRING(g_wfddeviceName, L"\\Device\\WFPSeeThru");
PDEVICE_OBJECT g_wfpWdmDeviceObject{};
WDFDRIVER g_wdfDriver{};
WDFDEVICE g_wdfDevice{};

/*++

Routine Description:
    DriverEntry initializes the driver andd is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

    Updated following https://learn.microsoft.com/en-us/windows-hardware/drivers/network/creating-a-device-object

Return Value:

    NTSTATUS

--*/
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    auto resetGlobalsOnError = wil::scope_exit([&]
    {
        g_wdfDriver = nullptr;
        g_wdfDevice = nullptr;
    });

    // Initialize Tracing
    NTSTATUS status = TraceLoggingRegister(g_routePolicyLoggingProvider);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("DriverEntry : TraceLoggingRegister failed : 0x%x\n", status);
        return status;
    }
    // TraceLoggingUnregister on failure 
    auto unRegisterTraceLoggingOnFailure = wil::scope_exit([]
    {
        TraceLoggingUnregister(g_routePolicyLoggingProvider);
    });


    TraceInfoMessage("DriverEntry", "Enter");
    const auto traceExit = wil::scope_exit([&]
    {
        TraceErrorMessage(status, "DriverEntry", "Exit");
    });

    // Register a cleanup callback so that we can cleanup our tracing provider
    // when the framework driver object is deleted during driver unload.
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = WFPSeeThruEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, WFPSeeThruEvtDeviceAdd);
    // config.DriverInitFlags = ###; // do NOT set WdfDriverInitNonPnpDriver
    config.EvtDriverUnload = WFPSeeThruEvtUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, &g_wdfDriver);
    RETURN_IF_NTSTATUS_FAILED(status, "DriverEntry", "WdfDriverCreate");

    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(g_wdfDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R);
    if (!deviceInit)
    {
        status = STATUS_NO_MEMORY;
        RETURN_IF_NTSTATUS_FAILED(status, "DriverEntry", "WdfControlDeviceInitAllocate");
    }
    // WdfDeviceInitFree on failure 
    auto wfdDeviceInitFreeOnError = wil::scope_exit([&]
    {
        WdfDeviceInitFree(deviceInit);
    });

    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    status = WdfDeviceInitAssignName(deviceInit, &g_wfddeviceName);
    RETURN_IF_NTSTATUS_FAILED(status, "DriverEntry", "WdfDeviceInitAssignName");

    // Create a framework device object
    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &g_wdfDevice);
    RETURN_IF_NTSTATUS_FAILED(status, "DriverEntry", "WdfDeviceCreate");

    // no failures from this point forward

    // Initialization of the framework device object is complete
    WdfControlFinishInitializing(g_wdfDevice);

    // Get the associated WDM device object
    g_wfpWdmDeviceObject = WdfDeviceWdmGetDeviceObject(g_wdfDevice);

    // release all scope guards
    wfdDeviceInitFreeOnError.release();
    unRegisterTraceLoggingOnFailure.release();
    resetGlobalsOnError.release();
    return STATUS_SUCCESS;
}

/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. We create and initialize a device object to
    represent a new instance of the device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
NTSTATUS WFPSeeThruEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE()

    const NTSTATUS status = WFPSeeThruCreateDevice(DeviceInit);
    RETURN_IF_NTSTATUS_FAILED(status, "WFPSeeThruEvtDeviceAdd", "WFPSeeThruCreateDevice");

    return STATUS_SUCCESS;
}

/*++
Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    void.

--*/
void WFPSeeThruEvtDriverContextCleanup(_In_ WDFOBJECT DriverObject)
{
    PAGED_CODE()

    DbgPrint("WFPSeeThruEvtDriverContextCleanup (%p)\n", DriverObject);

    TraceLoggingWrite(
        g_routePolicyLoggingProvider,
        "WFPSeeThruEvtDriverContextCleanup",
        TraceLoggingLevel(WINEVENT_LEVEL_INFO),
        TraceLoggingPointer(DriverObject, "WdfDriverObject"));

    // Stop Tracing
    TraceLoggingUnregister(g_routePolicyLoggingProvider);
}

// following https://learn.microsoft.com/en-us/windows-hardware/drivers/network/specifying-an-unload-function
// specified an EvtDriverUnload in the WDF_DRIVER_CONFIG used to create this driver instance
void WFPSeeThruEvtUnload(_In_ WDFDRIVER Driver)
{
    PAGED_CODE()

    UNREFERENCED_PARAMETER(Driver);

    DbgPrint("WFPSeeThruEvtUnload (%p)\n", Driver);

    TraceLoggingWrite(
        g_routePolicyLoggingProvider,
        "WFPSeeThruEvtUnload",
        TraceLoggingLevel(WINEVENT_LEVEL_INFO),
        TraceLoggingPointer(Driver, "WdfDriver"));
}
