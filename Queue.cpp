/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "Driver.h"
#include "Queue.h"
#include "Trace.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, WFPSeeThruQueueInitialize)
#pragma alloc_text (PAGE, WFPSeeThruEvtIoDeviceControl)
#pragma alloc_test (PAGE, WFPSeeThruEvtIoStop)
#endif

/*++

Routine Description:

     The I/O dispatch callbacks for the frameworks device object
     are configured in this function.

     A single default I/O Queue is configured for parallel request
     processing, and a driver context memory allocation is created
     to hold our structure QUEUE_CONTEXT.

Arguments:

    Device - Handle to a framework device object.

Return Value:

    void

--*/
NTSTATUS WFPSeeThruQueueInitialize(_In_ WDFDEVICE Device)
{
    PAGED_CODE()
    //
    // Configure a default queue so that requests that are not
    // configure-forwarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = WFPSeeThruEvtIoDeviceControl;
    queueConfig.EvtIoStop = WFPSeeThruEvtIoStop;

    WDFQUEUE queue{};
    const NTSTATUS status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    RETURN_IF_NTSTATUS_FAILED(status, "WFPSeeThruQueueInitialize", "WdfIoQueueCreate");

    return STATUS_SUCCESS;
}

/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_DEVICE_CONTROL request.

Arguments:

    Queue -  Handle to the framework queue object that is associated with the I/O request.

    Request - Handle to a framework request object.

    OutputBufferLength - Size of the output buffer in bytes

    InputBufferLength - Size of the input buffer in bytes

    IoControlCode - I/O control code.

Return Value:

    void

--*/
void WFPSeeThruEvtIoDeviceControl(
    _In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    PAGED_CODE()

    TraceLoggingWrite(
        g_routePolicyLoggingProvider,
        "WFPSeeThruEvtIoDeviceControl",
        TraceLoggingLevel(WINEVENT_LEVEL_INFO),
        TraceLoggingPointer(Queue, "queue"),
        TraceLoggingPointer(Request, "request"),
        TraceLoggingValue(OutputBufferLength, "outputBufferLength"),
        TraceLoggingValue(InputBufferLength, "InputBufferLength"),
        TraceLoggingValue(IoControlCode, "IoControlCode"));

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves the working state (D0).

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    ActionFlags - A bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS-typed flags
                  that identify the reason that the callback function is being called
                  and whether the request is cancelable.

Return Value:

    void

--*/
void WFPSeeThruEvtIoStop(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, ULONG ActionFlags)
{
    TraceLoggingWrite(
        g_routePolicyLoggingProvider,
        "WFPSeeThruEvtIoStop",
        TraceLoggingLevel(WINEVENT_LEVEL_INFO),
        TraceLoggingPointer(Queue, "queue"),
        TraceLoggingPointer(Request, "request"),
        TraceLoggingValue(ActionFlags, "actionFlags"));

    //
    // In most cases, the EvtIoStop callback function completes, cancels, or postpones
    // further processing of the I/O request.
    //
    // Typically, the driver uses the following rules:
    //
    // - If the driver owns the I/O request, it calls WdfRequestUnmarkCancelable
    //   (if the request is cancelable) and either calls WdfRequestStopAcknowledge
    //   with a Requeue value of TRUE, or it calls WdfRequestComplete with a
    //   completion status value of STATUS_SUCCESS or STATUS_CANCELLED.
    //
    //   Before it can call these methods safely, the driver must make sure that
    //   its implementation of EvtIoStop has exclusive access to the request.
    //
    //   In order to do that, the driver must synchronize access to the request
    //   to prevent other threads from manipulating the request concurrently.
    //   The synchronization method you choose will depend on your driver's design.
    //
    //   For example, if the request is held in a shared context, the EvtIoStop callback
    //   might acquire an internal driver lock, take the request from the shared context,
    //   and then release the lock. At this point, the EvtIoStop callback owns the request
    //   and can safely complete or requeue the request.
    //
    // - If the driver has forwarded the I/O request to an I/O target, it either calls
    //   WdfRequestCancelSentRequest to attempt to cancel the request, or it postpones
    //   further processing of the request and calls WdfRequestStopAcknowledge with
    //   a Requeue value of FALSE.
    //
    // A driver might choose to take no action in EvtIoStop for requests that are
    // guaranteed to complete in a small amount of time.
    //
    // In this case, the framework waits until the specified request is complete
    // before moving the device (or system) to a lower power state or removing the device.
    // Potentially, this inaction can prevent a system from entering its hibernation state
    // or another low system power state. In extreme cases, it can cause the system
    // to crash with bugcheck code 9F.
    //
}
