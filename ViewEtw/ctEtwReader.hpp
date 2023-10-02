#pragma once

// CPP Headers
#include <cassert>
#include <cwchar>
#include <algorithm>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// OS Headers
#include <Windows.h>
#include <guiddef.h>
// these 3 headers needed for evntrace.h
#include <wmistr.h>
#include <winmeta.h>
#include <evntcons.h>
#include <evntrace.h>
#include <optional>

#include <wil/resource.h>

#include "ctEtwRecord.hpp"

// Re-defining this flag from ntwmi.h to avoid pulling in a bunch of dependencies and conflict
#define EVENT_TRACE_USE_MS_FLUSH_TIMER 0x00000010  // FlushTimer value in milliseconds

namespace ctl
{
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // class ctEtwReader
    //
    // Encapsulates functioning as both an ETW controller and ETW consumer, allowing callers real-time
    //      access to ETW events from providers they specify. Consumers of this class additionally can
    //      provide a policy functor to enable a real-time callback over which events from the provider(s)
    //      they've specified they want stored in memory for later comparision. An ETL file is
    //      optionally generated with all events from the subscribed providers.
    //
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    class ctEtwReader
    {
    public:
        enum class QueueEvents
        {
            True,
            False,
        };

        ctEtwReader(QueueEvents queueEvents = QueueEvents::False) : m_queueEvents(queueEvents)
        {
        }

        template <typename T>
        ctEtwReader(T&& _eventCallback, QueueEvents queueEvents = QueueEvents::False) :
            m_eventCallback(std::forward<T>(_eventCallback)),
            m_queueEvents(queueEvents)
        {
        }

        ~ctEtwReader() noexcept
        {
            StopSession();
        }

        ctEtwReader(const ctEtwReader&) = delete;
        ctEtwReader& operator=(const ctEtwReader&) = delete;
        ctEtwReader(ctEtwReader&&) = delete;
        ctEtwReader& operator=(ctEtwReader&&) = delete;

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // StartSession()
        // 
        //  Creates and starts a trace session with the specified name
        //
        //  Arguments:
        //      szSessionName - null-terminated string for the unique name for the new trace session
        //
        //      szFileName - null-terminated string for the ETL trace file to be created
        //                   Optional parameter - pass NULL to not create a trace file
        //
        //      sessionGUID - unique GUID identifying this trace session to all providers
        //
        //      msFlushTimer - value, in milliseconds, of the ETW flush timer
        //                     Optional parameter - default value of 0 means system default is used
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void StartSession(
            _In_ PCWSTR szSessionName,
            _In_opt_ PCWSTR szFileName,
            const GUID& sessionGUID,
            int msFlushTimer = 0);

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // OpenSavedSession()
        // 
        //  Opens a trace session from the specific ETL file
        //
        //  Arguments:
        //      szFileName - null-terminated string for the ETL trace file to be read
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void OpenSavedSession(_In_ PCWSTR szFileName);

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // WaitForSession()
        //
        //  Waits on the session's thread handle until the thread exits.
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void WaitForSession() const noexcept;

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // StopSession()
        //
        //  Stops the event trace session that was started with StartSession()
        //      (and subsequently disables all providers)
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void StopSession() noexcept;

        //////////////////////////////////////////////////////////////////////////////////////////
        // 
        // EnableProviders()
        //
        // Enables the specified ETW providers in the existing trace session.
        // Fails if StartSession() has not been called successfully, or if the worker thread
        //      pumping events has stopped unexpectedly.
        //
        //  Arguments:
        //      providerGUIDs - std::vector of ETW Provider GUIDs that the caller wants enabled in this
        //                       trace session.  An empty std::vector enables no providers.
        //
        //      uLevel - the "Level" parameter passed to EnableTraceEx for providers specified
        //               default is TRACE_LEVEL_VERBOSE (all)
        //
        //      uMatchAnyKeyword - the "MatchAnyKeyword" parameter passed to EnableTraceEx
        //                         default is 0 (none)
        //
        //      uMatchAllKeyword - the "MatchAllKeyword" parameter passed to EnableTraceEx
        //                         default is 0 (none)
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void EnableProviders(
            const std::vector<GUID>& providerGUIDs,
            UCHAR uLevel = TRACE_LEVEL_VERBOSE,
            ULONGLONG uMatchAnyKeyword = 0,
            ULONGLONG uMatchAllKeyword = 0
        );

        //////////////////////////////////////////////////////////////////////////////////////////
        // 
        // DisableProviders()
        //
        // Disables the specified ETW providers in the existing trace session.
        // Fails if StartSession() has not been called successfully, or if the worker thread
        //      pumping events has stopped unexpectedly.
        //
        // Arguments:
        //      providerGUIDs - std::vector of ETW Provider GUIDs that the caller wants enabled in this
        //                       trace session.  An empty std::vector enables no providers.
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void DisableProviders(const std::vector<GUID>& providerGUIDs);

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // FlushEvents()
        //
        // Empties the internal queue of events found through the real-time event policy.
        // Can be called while events are still being processed real-time.
        //
        // Arguments:
        //      
        //
        // Returns:
        //      foundEvents - std::deque populated with all events found from the real-time even policy.
        //
        // Cannot Fail - Will not throw.
        //      - a copy is not made of the events - they are swapped into the provided std::deque,
        //        which cannot fail (no copying required, thus no OOM condition possible).
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        std::deque<ctEtwRecord> FlushEvents() noexcept;

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // CountEvents()
        //
        // Returns the current number of events queued through the real-time event policy.
        // Can be called while events are still being processed real-time.
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        size_t CountEvents() noexcept;

        //////////////////////////////////////////////////////////////////////////////////////////
        //
        // FlushSession()
        //
        // Explicitly flushes events from the internal ETW buffers
        // - is called internally when trying to Find or Remove
        // - exposing this publicly for callers who need it in other scenarios
        //
        //////////////////////////////////////////////////////////////////////////////////////////
        void FlushSession() const;

    private:
        static DWORD WINAPI ProcessTraceThread(LPVOID lpParameter);
        static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord);
        static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILE Buffer);
        static constexpr auto sleep_time = 50;

        void OpenTraceImpl(_In_ EVENT_TRACE_LOGFILE& eventLogfile);

        EVENT_TRACE_PROPERTIES* BuildEventTraceProperties(
            std::shared_ptr<BYTE[]>&,
            _In_ PCWSTR szSessionName,
            _In_opt_ PCWSTR szFileName,
            int msFlushTimer
        ) const;

        //////////////////////////////////////////////////////////////////////
        //
        // Encapsulate verifying the worker thread executing ProcessTrace
        // - hasn't stopped (which would mean no more events are collected)
        //
        //////////////////////////////////////////////////////////////////////
        void VerifySession();

        void AddEventRecord(const ctEtwRecord& trace) noexcept
        {
            if (m_queueEvents == QueueEvents::True)
            {
                const auto lock = m_lock.lock();
                m_eventRecordQueue.push_back(trace);
            }
        }

        // declaring common types to make methods less verbose
        typedef std::deque<ctEtwRecord>::const_iterator EtwRecordIterator;
        typedef std::deque<ctEtwRecord>::difference_type EtwRecordOffset;

        // member variables
        wil::critical_section m_lock;
        std::function<void(PEVENT_RECORD)> m_eventCallback{};
        std::deque<ctEtwRecord> m_eventRecordQueue{};
        EtwRecordOffset m_findCursor{};
        TRACEHANDLE m_sessionHandle{};
        TRACEHANDLE m_traceHandle{ INVALID_PROCESSTRACE_HANDLE };
        HANDLE m_threadHandle{};
        GUID m_sessionGUID{};
        std::optional<UINT> m_numBuffers{};
        const QueueEvents m_queueEvents{QueueEvents::False};
        bool m_openSavedSession{ false };
    };

    inline void ctEtwReader::StartSession(
        _In_ PCWSTR szSessionName, _In_opt_ PCWSTR szFileName, const GUID& sessionGUID, int msFlushTimer)
    {
        // block improper reentrancy
        if (m_sessionHandle != NULL ||
            m_traceHandle != INVALID_PROCESSTRACE_HANDLE ||
            m_threadHandle != nullptr)
        {
            throw std::runtime_error("ctEtwReader::StartSession is called while a session is already started");
        }

        m_sessionGUID = sessionGUID;

        std::shared_ptr<BYTE[]> pPropertyBuffer;
        EVENT_TRACE_PROPERTIES* pProperties = BuildEventTraceProperties(pPropertyBuffer, szSessionName, szFileName, msFlushTimer);
        ULONG ulReturn = ::StartTrace(&m_sessionHandle, szSessionName, pProperties);
        if (ERROR_ALREADY_EXISTS == ulReturn)
        {
            wprintf(
                L"\tctEtwReader::StartSession - session with the name %s is already running - stopping/restarting that session\n",
                szSessionName);
            // Try to stop the session by its session name
            EVENT_TRACE_PROPERTIES tempProperties{};
            tempProperties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
            ::ControlTrace(NULL, szSessionName, &tempProperties, EVENT_TRACE_CONTROL_STOP);

            // Try to start the session again
            ulReturn = ::StartTrace(&m_sessionHandle, szSessionName, pProperties);
        }
        if (ulReturn != ERROR_SUCCESS)
        {
            wprintf(L"\tctEtwReader::StartSession - StartTrace failed with error 0x%x\n", ulReturn);
            THROW_WIN32(ulReturn);
        }

        // Setup the EVENT_TRACE_LOGFILE to prepare the callback for real-time notification
        EVENT_TRACE_LOGFILE eventLogfile{};
        eventLogfile.LogFileName = nullptr;
        eventLogfile.LoggerName = const_cast<PWSTR>(szSessionName);
        eventLogfile.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        eventLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
        eventLogfile.BufferCallback = nullptr;
        eventLogfile.EventCallback = nullptr;
        eventLogfile.EventRecordCallback = EventRecordCallback;
        eventLogfile.Context = this;
        OpenTraceImpl(eventLogfile);
    }

    inline void ctEtwReader::OpenSavedSession(_In_ PCWSTR szFileName)
    {
        //
        // block improper reentrancy
        //
        if (m_sessionHandle != NULL ||
            m_traceHandle != INVALID_PROCESSTRACE_HANDLE ||
            m_threadHandle != nullptr)
        {
            wprintf(L"\tctEtwReader::StartSession is called while a session is already started\n");
            throw std::runtime_error("ctEtwReader::StartSession is called while a session is already started");
        }

        // Setup the EVENT_TRACE_LOGFILE to prepare the callback for real-time notification
        EVENT_TRACE_LOGFILE eventLogfile{};
        eventLogfile.LogFileName = const_cast<PWSTR>(szFileName);
        eventLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        eventLogfile.BufferCallback = BufferCallback;
        eventLogfile.EventCallback = nullptr;
        eventLogfile.EventRecordCallback = EventRecordCallback;
        eventLogfile.Context = this;
        OpenTraceImpl(eventLogfile);

        m_openSavedSession = true;
    }

    inline void ctEtwReader::OpenTraceImpl(_In_ EVENT_TRACE_LOGFILE& eventLogfile)
    {
        m_traceHandle = ::OpenTrace(&eventLogfile);
        if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const auto gle = ::GetLastError();
            wprintf(L"\tctEtwReader::StartSession - OpenTrace failed with error 0x%x\n", gle);
            THROW_WIN32(gle);
        }

        m_threadHandle = ::CreateThread(nullptr, 0, ProcessTraceThread, &m_traceHandle, 0, nullptr);
        if (nullptr == m_threadHandle)
        {
            const auto gle = ::GetLastError();
            wprintf(L"\tctEtwReader::StartSession - CreateThread failed with error 0x%x\n", gle);
            THROW_WIN32(gle);
        }

        // Quick check to see that the worker tread calling ProcessTrace didn't fail out
        VerifySession();
    }

    inline void ctEtwReader::VerifySession()
    {
        //
        // m_traceHandle will be reset after the user explicitly calls StopSession(),
        // - so only verify the thread if the user hasn't stopped the session
        //
        if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE && m_threadHandle != nullptr)
        {
            // Quick check to see that the worker tread calling ProcessTrace didn't fail out
            const auto dwWait = ::WaitForSingleObject(m_threadHandle, 0);
            if (WAIT_OBJECT_0 == dwWait)
            {
                // The worker thread already exited - ProcessTrace() failed
                DWORD dwError = 0;
                if (::GetExitCodeThread(m_threadHandle, &dwError))
                {
                    wprintf(
                        L"\tctEtwReader::VerifySession - the ProcessTrace worker thread exited with error 0x%x\n",
                        dwError);
                }
                else
                {
                    dwError = ::GetLastError();
                    wprintf(
                        L"\tctEtwReader::VerifySession - the ProcessTrace worker thread exited, but GetExitCodeThread failed with error 0x%x\n",
                        dwError);
                }

                // Close the thread handle now that it's dead
                CloseHandle(m_threadHandle);
                m_threadHandle = nullptr;
                THROW_WIN32(dwError);
            }
        }
    }

    inline void ctEtwReader::WaitForSession() const noexcept
    {
        if (m_threadHandle != nullptr)
        {
            const auto dwWait = ::WaitForSingleObject(m_threadHandle, INFINITE);
            FAIL_FAST_IF(dwWait != WAIT_OBJECT_0);
        }
    }

    inline void ctEtwReader::StopSession() noexcept
    {
        // initialize the EVENT_TRACE_PROPERTIES struct to stop the session
        if (m_sessionHandle != NULL)
        {
            EVENT_TRACE_PROPERTIES tempProperties{};
            tempProperties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
            tempProperties.Wnode.Guid = m_sessionGUID;
            tempProperties.Wnode.ClientContext = 1; // QPC
            tempProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

            const ULONG ulReturn = ::ControlTrace(m_sessionHandle, nullptr, &tempProperties, EVENT_TRACE_CONTROL_STOP);
            //
            // stops the session even when returned ERROR_MORE_DATA
            // - if this fails, there's nothing we can do to compensate
            //
            FAIL_FAST_IF_MSG(
                (ulReturn != ERROR_MORE_DATA) && (ulReturn != ERROR_SUCCESS),
                "ctEtwReader::StopSession - ControlTrace failed [%u] : cannot stop the trace session",
                ulReturn);
            m_sessionHandle = NULL;
        }

        // Close the handle from OpenTrace
        if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
        {
            // ProcessTrace is still unblocked and returns success when ERROR_CTX_CLOSE_PENDING is returned
            const auto error = ::CloseTrace(m_traceHandle);
            FAIL_FAST_IF_MSG(
                (ERROR_SUCCESS != error) && (ERROR_CTX_CLOSE_PENDING != error),
                "CloseTrace failed [%u] - thus will not unblock the APC thread processing events",
                error);
            m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
        }

        // the above call to CloseTrace should exit the thread
        if (m_threadHandle != nullptr)
        {
            const auto error = ::WaitForSingleObject(m_threadHandle, INFINITE);
            FAIL_FAST_IF_MSG(
                error != WAIT_OBJECT_0,
                "Failed waiting on ctEtwReader::StopSession thread to stop [%u - gle %u]",
                error, ::GetLastError());
            ::CloseHandle(m_threadHandle);
            m_threadHandle = nullptr;
        }
    }

    inline void ctEtwReader::EnableProviders(
        const std::vector<GUID>& providerGUIDs,
        UCHAR uLevel,
        ULONGLONG uMatchAnyKeyword,
        ULONGLONG uMatchAllKeyword)
    {
        // Block calling if an open session is not running
        VerifySession();

        // iterate through the std::vector of GUIDs, enabling each provider
        for (const auto& providerGUID : providerGUIDs)
        {
            const ULONG ulReturn = ::EnableTraceEx(
                &providerGUID,
                &m_sessionGUID,
                m_sessionHandle,
                TRUE,
                uLevel,
                uMatchAnyKeyword,
                uMatchAllKeyword,
                0,
                nullptr
            );
            if (ulReturn != ERROR_SUCCESS)
            {
                wprintf(L"\tctEtwReader::EnableProviders - EnableTraceEx failed with error 0x%x\n", ulReturn);
                THROW_WIN32(ulReturn);
            }
        }
    }

    inline EVENT_TRACE_PROPERTIES* ctEtwReader::BuildEventTraceProperties(
        std::shared_ptr<BYTE[]>& pPropertyBuffer,
        _In_ PCWSTR szSessionName,
        _In_opt_ PCWSTR szFileName,
        _In_ int msFlushTimer) const
    {
        //
        // Get buffer sizes in bytes and characters
        //     +1 for null-terminators
        //
        const size_t cchSessionLength = ::wcslen(szSessionName) + 1;
        const size_t cbSessionSize = cchSessionLength * sizeof(wchar_t);
        if (cbSessionSize < cchSessionLength)
        {
            wprintf(L"\tctEtwReader::BuildEventTraceProperties - the szSessionName was a bad argument\n");
            throw std::runtime_error("Overflow passing Session string to ctEtwReader");
        }
        size_t cchFileNameLength = 0;
        if (szFileName != nullptr)
        {
            cchFileNameLength = ::wcslen(szFileName) + 1;
        }

        const size_t cbFileNameSize = cchFileNameLength * sizeof(wchar_t);
        if (cbFileNameSize < cchFileNameLength)
        {
            wprintf(L"\tctEtwReader::BuildEventTraceProperties - the szFileName was a bad argument\n");
            throw std::runtime_error("Overflow passing Filename string to ctEtwReader");
        }

        const size_t cbProperties = sizeof(EVENT_TRACE_PROPERTIES) + cbSessionSize + cbFileNameSize;
        pPropertyBuffer.reset(new BYTE[cbProperties]);
        ::ZeroMemory(pPropertyBuffer.get(), cbProperties);
        //
        // Append the strings to the end of the struct
        //
        if (szFileName != nullptr)
        {
            // append the filename to the end of the struct
            ::CopyMemory(
                pPropertyBuffer.get() + sizeof(EVENT_TRACE_PROPERTIES),
                szFileName,
                cbFileNameSize
            );
            // append the session name to the end of the struct
            ::CopyMemory(
                pPropertyBuffer.get() + sizeof(EVENT_TRACE_PROPERTIES) + cbFileNameSize,
                szSessionName,
                cbSessionSize
            );
        }
        else
        {
            // append the session name to the end of the struct
            ::CopyMemory(
                pPropertyBuffer.get() + sizeof(EVENT_TRACE_PROPERTIES),
                szSessionName,
                cbSessionSize
            );
        }
        //
        // Set the required fields for starting a new session:
        //   Wnode.BufferSize 
        //   Wnode.Guid 
        //   Wnode.ClientContext 
        //   Wnode.Flags 
        //   LogFileMode 
        //   LogFileNameOffset 
        //   LoggerNameOffset 
        //
        auto* pProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(pPropertyBuffer.get());
        pProperties->MinimumBuffers = 1; // smaller will make it easier to flush - explicitly not performance sensitive
        pProperties->Wnode.BufferSize = static_cast<ULONG>(cbProperties);
        pProperties->Wnode.Guid = m_sessionGUID;
        pProperties->Wnode.ClientContext = 1; // QPC
        pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pProperties->LogFileNameOffset = nullptr == szFileName
            ? 0
            : static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES));
        pProperties->LoggerNameOffset = nullptr == szFileName
            ? static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES))
            : static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + cbFileNameSize);
        if (msFlushTimer != 0)
        {
            pProperties->LogFileMode |= EVENT_TRACE_USE_MS_FLUSH_TIMER;
            pProperties->FlushTimer = msFlushTimer;
        }

        return pProperties;
    }

    inline void ctEtwReader::DisableProviders(const std::vector<GUID>& providerGUIDs)
    {
        // Block calling if an open session is not running
        VerifySession();

        // iterate through the std::vector of GUIDs, disabling each provider
        for (const auto& providerGUID : providerGUIDs)
        {
            const ULONG ulReturn = ::EnableTraceEx(
                &providerGUID,
                &m_sessionGUID,
                m_sessionHandle,
                FALSE,
                0,
                0,
                0,
                0,
                nullptr
            );
            if (ulReturn != ERROR_SUCCESS)
            {
                wprintf(L"\tctEtwReader::DisableProviders - EnableTraceEx failed with error 0x%x\n", ulReturn);
                THROW_WIN32(ulReturn);
            }
        }
    }

    inline void ctEtwReader::FlushSession() const
    {
        if (m_sessionHandle != NULL)
        {
            EVENT_TRACE_PROPERTIES tempProperties{};
            tempProperties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
            tempProperties.Wnode.Guid = m_sessionGUID;
            tempProperties.Wnode.ClientContext = 1; // QPC
            tempProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            //
            // Stop the session
            //
            const ULONG ulReturn = ::ControlTrace(
                m_sessionHandle,
                nullptr,
                &tempProperties,
                EVENT_TRACE_CONTROL_FLUSH
            );
            //
            // stops the session even when returned ERROR_MORE_DATA
            // - if this fails, there's nothing we can do to compensate
            //
            if (ulReturn != ERROR_MORE_DATA && ulReturn != ERROR_SUCCESS)
            {
                wprintf(L"\tctEtwReader::FlushSession - ControlTrace failed with error 0x%x\n", ulReturn);
                THROW_WIN32(ulReturn);
            }
        }
    }

    inline size_t ctEtwReader::CountEvents() noexcept
    {
        const auto lock = m_lock.lock();
        return m_eventRecordQueue.size();
    }

    inline std::deque<ctEtwRecord> ctEtwReader::FlushEvents() noexcept
    {
        const auto lock = m_lock.lock();
        std::deque<ctEtwRecord> out_queue;
        m_eventRecordQueue.swap(out_queue);
        m_eventRecordQueue.clear();
        return out_queue;
    }

    inline DWORD WINAPI ctEtwReader::ProcessTraceThread(LPVOID lpParameter)
    {
        // Must call ProcessTrace to start the events going to the callback
        // this thread remains while events are pumped through the callback
        return ::ProcessTrace(static_cast<TRACEHANDLE*>(lpParameter), 1, nullptr, nullptr);
    }

    inline VOID WINAPI ctEtwReader::EventRecordCallback(PEVENT_RECORD pEventRecord)
    {
        auto* pEventReader = static_cast<ctEtwReader*>(pEventRecord->UserContext);

        try
        {
            //
            // When opening a saved session from an ETL file, the first event record
            // contains diagnostic information about the contents of the trace - the
            // most important (for us) field being the number of buffers written. By
            // saving this value, we can consume it later on inside BufferCallback to
            // force ProcessTrace() to return when the entire contents of the session
            // have been read.
            //
            bool process = true;
            if (pEventReader->m_openSavedSession && !pEventReader->m_numBuffers.has_value())
            {
                const ctEtwRecord eventMessage(pEventRecord);
                std::wstring task;
                if (eventMessage.queryTaskName(task) && task == L"EventTrace")
                {
                    process = false;
                    ctEtwRecord::ctPropertyPair pair;
                    if (eventMessage.queryEventProperty(L"BuffersWritten", pair))
                    {
                        pEventReader->m_numBuffers = *reinterpret_cast<int*>(pair.first.get());
                    }
                }
            }

            if (process)
            {
                if (pEventReader->m_eventCallback)
                {
                    pEventReader->m_eventCallback(pEventRecord);
                }

                const ctEtwRecord eventMessage(pEventRecord);
                pEventReader->AddEventRecord(eventMessage);
            }
        }
        catch (...)
        {
            // the above could throw std::exception objects (e.g. std::bad_alloc)
            // - or wil exceptions objects (which derive from std::exception)
        }
    }

    inline ULONG WINAPI ctEtwReader::BufferCallback(PEVENT_TRACE_LOGFILE Buffer)
    {
        const auto* pEventReader = static_cast<ctEtwReader*>(Buffer->Context);
        if (pEventReader->m_numBuffers)
        {
            return Buffer->BuffersRead != pEventReader->m_numBuffers;
        }
        return false;
    }
} // namespace
