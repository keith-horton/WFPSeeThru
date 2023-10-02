// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

// CPP Headers
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <format>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// OS Headers
#include <Windows.h>
#include <winsock2.h>
#include <Rpc.h>
// including these to get IP helper functions
#include <WS2tcpip.H>
#include <mstcpip.h>
// these 3 headers needed for evntrace.h
#include <wmistr.h>
#include <winmeta.h>
#include <evntcons.h>
#include <evntrace.h>
#include <Tdh.h>
#include <Sddl.h>

#include <wil/resource.h>

namespace ctl
{
    namespace uuid {

        inline std::wstring uuid_to_string(_In_ UUID _guid)
        {
            RPC_WSTR wszUuid = nullptr;
            THROW_IF_WIN32_ERROR(::UuidToStringW(&_guid, &wszUuid));
            const auto wszUuidDeleter = wil::scope_exit([&] { ::RpcStringFreeW(&wszUuid); });
            return std::wstring{reinterpret_cast<wchar_t*>(wszUuid)};
        }

        inline GUID string_to_uuid(_In_ PCWSTR _guid)
        {
            GUID returned_uuid;
            THROW_IF_WIN32_ERROR(::UuidFromStringW(reinterpret_cast<RPC_WSTR>(const_cast<PWSTR>(_guid)), &returned_uuid));
            return returned_uuid;
        }

        inline std::wstring generate_uuid()
        {
            UUID tempUuid;
            THROW_IF_WIN32_ERROR(::UuidCreate(&tempUuid));
            return uuid_to_string(tempUuid);
        }

    }

    ////////////////////////////////////////////////////////////////////////////////
    //
    //  class ctEtwRecord
    //
    //  Encapsulates accessing all the various properties one can potentially
    //      gather from a EVENT_RECORD structure passed to the consumer from ETW.
    //
    //  The constructor takes a ptr to the EVENT_RECORD to encapsulate, and makes
    //      a deep copy of all embedded and referenced data structures to access
    //      with the   getter member functions.
    //
    //  There are 2 method-types exposed:    get*() and  query*()
    //        get* functions have no parameters, and always return the associated
    //          value.  They will always have a value to return from any event.
    //
    //       query* functions take applicable [out] as parameters, and return bool.
    //          The values they retrieve are not guaranteed to be in all events,
    //          and will return false if they don't exist in the encapsulated event.
    //
    ////////////////////////////////////////////////////////////////////////////////
    class ctEtwRecord
    {
    public:
        // A public typedef to access the pair class containing the property data
        typedef std::pair<std::shared_ptr<BYTE[]>, ULONG> ctPropertyPair;

        ctEtwRecord() noexcept = default;
        ~ctEtwRecord() noexcept = default;
        ctEtwRecord(const ctEtwRecord&) noexcept = default;
        ctEtwRecord& operator=(_In_ const ctEtwRecord&) noexcept = default;
        ctEtwRecord(ctEtwRecord&&) noexcept = default;
        ctEtwRecord& operator=(ctEtwRecord&&) noexcept = default;

        ctEtwRecord(_In_ PEVENT_RECORD);
        ctEtwRecord& operator=(_In_ PEVENT_RECORD);

        void swap(ctEtwRecord&) noexcept;

        void writeRecord(std::wstring&) const;

        std::wstring writeRecord() const
        {
            std::wstring wsRecord;
            writeRecord(wsRecord);
            return wsRecord;
        }

        void writeFormattedMessage(std::wstring&, bool) const;

        std::wstring writeFormattedMessage(bool _details) const
        {
            std::wstring wsRecord;
            writeFormattedMessage(wsRecord, _details);
            return wsRecord;
        }

        bool operator==(_In_ const ctEtwRecord&) const;
        bool operator!=(_In_ const ctEtwRecord&) const;

        /////////////////////////////////////////////////////////////
        //
        // EVENT_HEADER fields (8)
        //
        /////////////////////////////////////////////////////////////
        ULONG getThreadId() const noexcept;
        ULONG getProcessId() const noexcept;
        LARGE_INTEGER getTimeStamp() const noexcept;
        GUID getProviderId() const noexcept;
        GUID getActivityId() const noexcept;
        bool queryKernelTime(_Out_ ULONG*) const noexcept;
        bool queryUserTime(_Out_ ULONG*) const noexcept;
        ULONG64 getProcessorTime() const noexcept;

        /////////////////////////////////////////////////////////////
        //
        // EVENT_DESCRIPTOR fields (7)
        //
        /////////////////////////////////////////////////////////////
        USHORT getEventId() const noexcept;
        UCHAR getVersion() const noexcept;
        UCHAR getChannel() const noexcept;
        UCHAR getLevel() const noexcept;
        UCHAR getOpcode() const noexcept;
        USHORT getTask() const noexcept;
        ULONGLONG getKeyword() const noexcept;

        /////////////////////////////////////////////////////////////
        //
        // ETW_BUFFER_CONTEXT fields (3)
        //
        /////////////////////////////////////////////////////////////
        UCHAR getProcessorNumber() const noexcept;
        UCHAR getAlignment() const noexcept;
        USHORT getLoggerId() const noexcept;

        /////////////////////////////////////////////////////////////
        //
        // EVENT_HEADER_EXTENDED_DATA_ITEM options (6)
        //
        /////////////////////////////////////////////////////////////
        bool queryRelatedActivityId(_Out_ GUID*) const noexcept;
        bool querySID(_Out_ std::shared_ptr<BYTE[]>&, _Out_ size_t*) const;
        bool queryTerminalSessionId(_Out_ ULONG*) const noexcept;
        bool queryTransactionInstanceId(_Out_ ULONG*) const noexcept;
        bool queryTransactionParentInstanceId(_Out_ ULONG*) const noexcept;
        bool queryTransactionParentGuid(_Out_ GUID*) const noexcept;

        /////////////////////////////////////////////////////////////
        //
        // TRACE_EVENT_INFO options (16)
        //
        /////////////////////////////////////////////////////////////
        bool queryProviderGuid(_Out_ GUID*) const noexcept;
        bool queryDecodingSource(_Out_ DECODING_SOURCE*) const noexcept;
        bool queryProviderName(_Out_ std::wstring&) const;
        bool queryLevelName(_Out_ std::wstring&) const;
        bool queryChannelName(_Out_ std::wstring&) const;
        bool queryKeywords(_Out_ std::vector<std::wstring>&) const;
        bool queryTaskName(_Out_ std::wstring&) const;
        bool queryOpCodeName(_Out_ std::wstring&) const;
        bool queryEventMessage(_Out_ std::wstring&) const;
        bool queryProviderMessageName(_Out_ std::wstring&) const;
        bool queryPropertyCount(_Out_ ULONG*) const noexcept;
        bool queryTopLevelPropertyCount(_Out_ ULONG*) const noexcept;
        bool queryEventPropertyStringValue(_Out_ std::wstring&) const;
        bool queryEventPropertyName(_In_ ULONG ulIndex, _Out_ std::wstring& out) const;
        bool queryEventProperty(_In_ PCWSTR, _Out_ std::wstring&) const;
        bool queryEventProperty(_In_ PCWSTR, _Out_ ctPropertyPair&) const;
        bool queryEventProperty(_In_ ULONG, _Out_ std::wstring&) const;

    private:
        std::wstring buildEventPropertyString(ULONG) const;

        // eventHeader and etwBufferContext are just shallow-copies
        // of the the EVENT_HEADER and ETW_BUFFER_CONTEXT structs.
        EVENT_HEADER m_eventHeader{};
        ETW_BUFFER_CONTEXT m_etwBufferContext{};

        // m_eventHeaderExtendedData and m_pEventHeaderData stores a deep-copy
        // of the the EVENT_HEADER_EXTENDED_DATA_ITEM struct.
        std::vector<EVENT_HEADER_EXTENDED_DATA_ITEM> m_eventHeaderExtendedData{};
        std::vector<std::shared_ptr<BYTE[]>> m_pEventHeaderData{};

        // m_traceEventInfo stores a deep copy of the TRACE_EVENT_INFO struct.
        std::shared_ptr<BYTE[]> m_traceEventInfo{};
        ULONG m_cbTraceEventInfo{};

        // m_traceProperties stores an array of all properties
        std::vector<ctPropertyPair> m_traceProperties{};

        typedef std::pair<std::shared_ptr<WCHAR[]>, ULONG> ctMappingPair;
        std::vector<ctMappingPair> m_traceMapping{};

        // need to allow a default empty constructor, so must track initialization status
        bool m_bInit{ false };
    };


    inline
        ctEtwRecord::ctEtwRecord(_In_ PEVENT_RECORD in_pRecord)
        : m_eventHeader(in_pRecord->EventHeader),
        m_etwBufferContext(in_pRecord->BufferContext)
    {
        if (in_pRecord->ExtendedDataCount > 0)
        {
            // Copying the EVENT_HEADER_EXTENDED_DATA_ITEM requires a deep-copy its data buffer
            //    and to point the local struct at the locally allocated and copied buffer
            //    since we won't have direct access to the original buffer later
            m_eventHeaderExtendedData.resize(in_pRecord->ExtendedDataCount);
            m_pEventHeaderData.resize(in_pRecord->ExtendedDataCount);

            for (unsigned uCount = 0; uCount < m_eventHeaderExtendedData.size(); ++uCount)
            {
                PEVENT_HEADER_EXTENDED_DATA_ITEM tempItem = in_pRecord->ExtendedData;
                tempItem += uCount;

                std::shared_ptr<BYTE[]> pTempBytes(new BYTE[tempItem->DataSize]);
                memcpy_s(
                    pTempBytes.get(),
                    tempItem->DataSize,
                    reinterpret_cast<BYTE*>(tempItem->DataPtr),
                    tempItem->DataSize);

                m_pEventHeaderData[uCount] = pTempBytes;
                m_eventHeaderExtendedData[uCount] = *tempItem;
                m_eventHeaderExtendedData[uCount].DataPtr = reinterpret_cast<ULONGLONG>(0ULL + m_pEventHeaderData[
                    uCount].get());
            }
        }

        if (m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY)
        {
            m_cbTraceEventInfo = in_pRecord->UserDataLength;
            m_traceEventInfo.reset(new BYTE[m_cbTraceEventInfo]);
            memcpy_s(
                m_traceEventInfo.get(),
                m_cbTraceEventInfo,
                in_pRecord->UserData,
                m_cbTraceEventInfo);
        }
        else
        {
            m_cbTraceEventInfo = 0;
            auto tdhStatus = ::TdhGetEventInformation(in_pRecord, 0, nullptr, nullptr, &m_cbTraceEventInfo);
            if (ERROR_INSUFFICIENT_BUFFER == tdhStatus)
            {
                m_traceEventInfo.reset(new BYTE[m_cbTraceEventInfo]);
                tdhStatus = ::TdhGetEventInformation(
                    in_pRecord, 0, nullptr, reinterpret_cast<PTRACE_EVENT_INFO>(m_traceEventInfo.get()),
                    &m_cbTraceEventInfo);
            }
            if (tdhStatus != ERROR_SUCCESS)
            {
                THROW_WIN32(tdhStatus);
            }

            // retrieve all property data points - need to do this in the constructor since the original EVENT_RECORD is required
            auto* pByteInfo = m_traceEventInfo.get();
            auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
            const ULONG total_properties = pTraceInfo->TopLevelPropertyCount;
            if (total_properties > 0)
            {
                // variables for TdhFormatProperty
                USHORT UserDataLength = in_pRecord->UserDataLength;
                auto* UserData = static_cast<PBYTE>(in_pRecord->UserData);
                //
                // go through event event, and pull out the necessary data
                //
                for (ULONG property_count = 0; property_count < total_properties; ++property_count)
                {
                    if (pTraceInfo->EventPropertyInfoArray[property_count].Flags & PropertyStruct)
                    {
                        //
                        // currently not supporting deep-copying event data of structs
                        //
                        ::OutputDebugStringW(
                            std::format(
                                L"ctEtwRecord cannot support a PropertyStruct : provider %s, property %s, event id %u",
                                uuid::uuid_to_string(m_eventHeader.ProviderId).c_str(),
                                reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[
                                    property_count].NameOffset),
                                m_eventHeader.EventDescriptor.Id).c_str());

                        m_traceMapping.emplace_back(std::shared_ptr<WCHAR[]>(), 0);
                        m_traceProperties.emplace_back(std::shared_ptr<BYTE[]>(), 0);
                    }
                    else if (pTraceInfo->EventPropertyInfoArray[property_count].count > 1)
                    {
                        //
                        // currently not supporting deep-copying event data of arrays
                        //
                        ::OutputDebugStringW(
                            std::format(
                                L"ctEtwRecord cannot support an array property size %u : provider %s, property %s, event id %u",
                                pTraceInfo->EventPropertyInfoArray[property_count].count,
                                uuid::uuid_to_string(m_eventHeader.ProviderId).c_str(),
                                reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[
                                    property_count].NameOffset),
                                m_eventHeader.EventDescriptor.Id).c_str());

                        m_traceMapping.emplace_back(std::shared_ptr<WCHAR[]>(), 0);
                        m_traceProperties.emplace_back(std::shared_ptr<BYTE[]>(), 0);
                    }
                    else
                    {
                        //
                        // define the event we want with a PROPERTY_DATA_DESCRIPTOR
                        //
                        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
                        dataDescriptor.PropertyName = reinterpret_cast<ULONGLONG>(pByteInfo + pTraceInfo->
                            EventPropertyInfoArray[property_count].NameOffset);
                        dataDescriptor.ArrayIndex = ULONG_MAX;
                        dataDescriptor.Reserved = 0UL;
                        //
                        // get the buffer size first
                        //
                        ULONG cbPropertyData = 0;
                        tdhStatus = ::TdhGetPropertySize(
                            in_pRecord,
                            0, // not using WPP or 'classic' ETW
                            nullptr, // not using WPP or 'classic' ETW
                            1, // one property at a time - not support structs of data at this time
                            &dataDescriptor,
                            &cbPropertyData);
                        THROW_IF_WIN32_ERROR(tdhStatus);
                        //
                        // now allocate the required buffer, and copy the data
                        // - only if the buffer size > 0
                        //
                        std::shared_ptr<BYTE[]> pPropertyData;
                        if (cbPropertyData > 0)
                        {
                            pPropertyData.reset(new BYTE[cbPropertyData]);
                            tdhStatus = ::TdhGetProperty(
                                in_pRecord,
                                0, // not using WPP or 'classic' ETW
                                nullptr, // not using WPP or 'classic' ETW
                                1, // one property at a time - not support structs of data at this time
                                &dataDescriptor,
                                cbPropertyData,
                                pPropertyData.get());
                            THROW_IF_WIN32_ERROR(tdhStatus);
                        }
                        m_traceProperties.emplace_back(pPropertyData, cbPropertyData);

                        //
                        // additionally capture the mapped string for the property, if it exists
                        //
                        DWORD dwMapInfoSize = 0;
                        std::shared_ptr<BYTE[]> pPropertyMap;
                        const auto szMapName = reinterpret_cast<PWSTR>(pByteInfo + pTraceInfo->EventPropertyInfoArray[
                            property_count].nonStructType.MapNameOffset);
                        // first query the size needed
                        tdhStatus = ::TdhGetEventMapInformation(in_pRecord, szMapName, nullptr, &dwMapInfoSize);
                        if (ERROR_INSUFFICIENT_BUFFER == tdhStatus)
                        {
                            pPropertyMap.reset(new BYTE[dwMapInfoSize]);
                            tdhStatus = ::TdhGetEventMapInformation(
                                in_pRecord,
                                szMapName,
                                reinterpret_cast<PEVENT_MAP_INFO>(pPropertyMap.get()),
                                &dwMapInfoSize
                            );
                        }
                        switch (tdhStatus)
                        {
                        case ERROR_SUCCESS:
                            // all good - do nothing
                            break;
                        case ERROR_NOT_FOUND:
                            // this is OK to keep this event - there just wasn't a mapping for a formatted string
                            pPropertyMap.reset();
                            break;
                        default:
                            // any other error is an unexpected failure
                            pPropertyMap.reset();
                        }
                        //
                        // if we successfully retrieved the property info
                        // format the mapped property value
                        //
                        if (pPropertyMap)
                        {
                            USHORT property_length = pTraceInfo->EventPropertyInfoArray[property_count].length;
                            // per MSDN, must manually set the length for TDH_OUTTYPE_IPV6
                            if ((TDH_INTYPE_BINARY == pTraceInfo->EventPropertyInfoArray[property_count].nonStructType.InType)
                                &&
                                (TDH_OUTTYPE_IPV6 == pTraceInfo->EventPropertyInfoArray[property_count].nonStructType.OutType))
                            {
                                property_length = static_cast<USHORT>(sizeof IN6_ADDR);
                            }
                            const ULONG pointer_size =
                                (in_pRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

                            ULONG formattedPropertySize = 0;
                            USHORT UserDataConsumed = 0;
                            std::shared_ptr<WCHAR[]> formatted_value;
                            tdhStatus = ::TdhFormatProperty(
                                pTraceInfo,
                                reinterpret_cast<PEVENT_MAP_INFO>(pPropertyMap.get()),
                                pointer_size,
                                pTraceInfo->EventPropertyInfoArray[property_count].nonStructType.InType,
                                pTraceInfo->EventPropertyInfoArray[property_count].nonStructType.OutType,
                                property_length,
                                UserDataLength,
                                UserData,
                                &formattedPropertySize,
                                nullptr,
                                &UserDataConsumed);
                            if (ERROR_INSUFFICIENT_BUFFER == tdhStatus)
                            {
                                formatted_value.reset(new WCHAR[formattedPropertySize / sizeof(WCHAR)]);
                                tdhStatus = ::TdhFormatProperty(
                                    pTraceInfo,
                                    reinterpret_cast<PEVENT_MAP_INFO>(pPropertyMap.get()),
                                    pointer_size,
                                    pTraceInfo->EventPropertyInfoArray[property_count].nonStructType.InType,
                                    pTraceInfo->EventPropertyInfoArray[property_count].nonStructType.OutType,
                                    property_length,
                                    UserDataLength,
                                    UserData,
                                    &formattedPropertySize,
                                    formatted_value.get(),
                                    &UserDataConsumed
                                );
                            }
                            if (tdhStatus != ERROR_SUCCESS)
                            {
                                m_traceMapping.emplace_back(std::shared_ptr<WCHAR[]>(), 0);
                            }
                            else
                            {
                                UserDataLength -= UserDataConsumed;
                                UserData += UserDataConsumed;
                                // now add the value/size pair to the member std::vector storing all properties
                                m_traceMapping.emplace_back(formatted_value, formattedPropertySize);
                            }
                        }
                        else
                        {
                            // store null values
                            m_traceMapping.emplace_back(std::shared_ptr<WCHAR[]>(), 0);
                        }
                    }
                }
            }
        }

        m_bInit = true;
    }

    inline ctEtwRecord& ctEtwRecord::operator=(_In_ PEVENT_RECORD out_record)
    {
        ctEtwRecord temp(out_record);
        swap(temp);
        m_bInit = true; // explicitly flag to true
        return *this;
    }

    inline void ctEtwRecord::swap(ctEtwRecord& in_event) noexcept
    {
        using std::swap;
        swap(m_eventHeaderExtendedData, in_event.m_eventHeaderExtendedData);
        swap(m_pEventHeaderData, in_event.m_pEventHeaderData);
        swap(m_traceEventInfo, in_event.m_traceEventInfo);
        swap(m_cbTraceEventInfo, in_event.m_cbTraceEventInfo);
        swap(m_traceProperties, in_event.m_traceProperties);
        swap(m_traceMapping, in_event.m_traceMapping);
        swap(m_bInit, in_event.m_bInit);
        //
        // manually swap these structures
        //
        EVENT_HEADER tempHeader{};
        memcpy_s(
            &(tempHeader), // this to temp
            sizeof(EVENT_HEADER),
            &(m_eventHeader),
            sizeof(EVENT_HEADER));
        memcpy_s(
            &(m_eventHeader), // in_event to this
            sizeof(EVENT_HEADER),
            &(in_event.m_eventHeader),
            sizeof(EVENT_HEADER));
        memcpy_s(
            &(in_event.m_eventHeader), // temp to in_event
            sizeof(EVENT_HEADER),
            &(tempHeader),
            sizeof(EVENT_HEADER));

        ETW_BUFFER_CONTEXT tempBuffContext;
        memcpy_s(
            &(tempBuffContext), // this to temp
            sizeof(ETW_BUFFER_CONTEXT),
            &(m_etwBufferContext),
            sizeof(ETW_BUFFER_CONTEXT));
        memcpy_s(
            &(m_etwBufferContext), // in_event to this
            sizeof(ETW_BUFFER_CONTEXT),
            &(in_event.m_etwBufferContext),
            sizeof(ETW_BUFFER_CONTEXT));
        memcpy_s(
            &(in_event.m_etwBufferContext), // temp to in_event
            sizeof(ETW_BUFFER_CONTEXT),
            &(tempBuffContext),
            sizeof(ETW_BUFFER_CONTEXT));
    }

    inline void swap(ctEtwRecord& a, ctEtwRecord& b) noexcept
    {
        a.swap(b);
    }

    inline void ctEtwRecord::writeRecord(std::wstring& out_wsString) const
    {
        // write to a temp string - but use the caller's buffer
        std::wstring wsData;
        wsData.swap(out_wsString);
        wsData.clear();

        constexpr unsigned cch_StackBuffer = 100;
        wchar_t arStackBuffer[cch_StackBuffer]{};

        //
        //  Data from EVENT_HEADER properties
        //
        wsData += L"\n\tThread ID ";
        _ultow_s(getThreadId(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tProcess ID ";
        _ultow_s(getProcessId(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tTime Stamp ";
        _ui64tow_s(getTimeStamp().QuadPart, arStackBuffer, cch_StackBuffer, 16);
        wsData += L"0x";
        wsData += arStackBuffer;

        wsData += L"\n\tProvider ID ";
        wsData += ctl::uuid::uuid_to_string(getProviderId());

        wsData += L"\n\tActivity ID ";
        wsData += ctl::uuid::uuid_to_string(getActivityId());

        ULONG ulData = 0;
        if (queryKernelTime(&ulData))
        {
            wsData += L"\n\tKernel Time ";
            _ultow_s(ulData, arStackBuffer, 16);
            wsData += L"0x";
            wsData += arStackBuffer;
        }

        if (queryUserTime(&ulData))
        {
            wsData += L"\n\tUser Time ";
            _ultow_s(ulData, arStackBuffer, 16);
            wsData += L"0x";
            wsData += arStackBuffer;
        }

        wsData += L"\n\tProcessor Time: ";
        _ui64tow_s(getProcessorTime(), arStackBuffer, cch_StackBuffer, 16);
        wsData += L"0x";
        wsData += arStackBuffer;

        //
        //  Data from EVENT_DESCRIPTOR properties
        //
        wsData += L"\n\tEvent ID ";
        _itow_s(getEventId(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tVersion ";
        _itow_s(getVersion(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tChannel ";
        _itow_s(getChannel(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tLevel ";
        _itow_s(getLevel(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tOpCode ";
        _itow_s(getOpcode(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tTask ";
        _itow_s(getTask(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tKeyword ";
        _ui64tow_s(getKeyword(), arStackBuffer, cch_StackBuffer, 16);
        wsData += L"0x";
        wsData += arStackBuffer;

        //
        //  Data from ETW_BUFFER_CONTEXT properties
        //
        wsData += L"\n\tProcessor ";
        _itow_s(getProcessorNumber(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tAlignment ";
        _itow_s(getAlignment(), arStackBuffer, 10);
        wsData += arStackBuffer;

        wsData += L"\n\tLogger ID ";
        _itow_s(getLoggerId(), arStackBuffer, 10);
        wsData += arStackBuffer;

        //
        //  Data from EVENT_HEADER_EXTENDED_DATA_ITEM properties
        //
        GUID guidBuf{};
        if (queryRelatedActivityId(&guidBuf))
        {
            wsData += L"\n\tRelated Activity ID ";
            wsData += ctl::uuid::uuid_to_string(guidBuf);
        }

        std::shared_ptr<BYTE[]> pSID;
        size_t cbSID = 0;
        if (querySID(pSID, &cbSID))
        {
            wsData += L"\n\tSID ";
            PWSTR szSID = nullptr;
            const auto freeSidString = wil::scope_exit([&] { ::LocalFree(szSID); });
            THROW_IF_WIN32_BOOL_FALSE(::ConvertSidToStringSidW(pSID.get(), &szSID));
            wsData += szSID;
        }

        if (queryTerminalSessionId(&ulData))
        {
            wsData += L"\n\tTerminal Session ID ";
            _ultow_s(ulData, arStackBuffer, 10);
            wsData += arStackBuffer;
        }

        if (queryTransactionInstanceId(&ulData))
        {
            wsData += L"\n\tTransaction Instance ID ";
            _ultow_s(ulData, arStackBuffer, 10);
            wsData += arStackBuffer;
        }

        if (queryTransactionParentInstanceId(&ulData))
        {
            wsData += L"\n\tTransaction Parent Instance ID ";
            _ultow_s(ulData, arStackBuffer, 10);
            wsData += arStackBuffer;
        }

        if (queryTransactionParentGuid(&guidBuf))
        {
            wsData += L"\n\tTransaction Parent GUID ";
            wsData += ctl::uuid::uuid_to_string(guidBuf);
        }

        //
        //  Accessors for TRACE_EVENT_INFO properties
        //
        if (queryProviderGuid(&guidBuf))
        {
            wsData += L"\n\tProvider GUID ";
            wsData += ctl::uuid::uuid_to_string(guidBuf);
        }

        DECODING_SOURCE dSource{};
        if (queryDecodingSource(&dSource))
        {
            wsData += L"\n\tDecoding Source ";
            switch (dSource)
            {
            case DecodingSourceXMLFile:
                wsData += L"DecodingSourceXMLFile";
                break;
            case DecodingSourceWbem:
                wsData += L"DecodingSourceWbem";
                break;
            case DecodingSourceWPP:
                wsData += L"DecodingSourceWPP";
            case DecodingSourceTlg:
                wsData += L"DecodingSourceTlg";
                break;
            }
        }

        std::wstring wsText;
        if (queryProviderName(wsText))
        {
            wsData += L"\n\tProvider Name " + wsText;
        }

        if (queryLevelName(wsText))
        {
            wsData += L"\n\tLevel Name " + wsText;
        }

        if (queryChannelName(wsText))
        {
            wsData += L"\n\tChannel Name " + wsText;
        }

        std::vector<std::wstring> keywordData;
        if (queryKeywords(keywordData))
        {
            wsData += L"\n\tKeywords [";
            for (const auto& keyword : keywordData)
            {
                wsData += keyword;
            }
            wsData += L"]";
        }

        if (queryTaskName(wsText))
        {
            wsData += L"\n\tTask Name " + wsText;
        }

        if (queryOpCodeName(wsText))
        {
            wsData += L"\n\tOpCode Name " + wsText;
        }

        if (queryEventMessage(wsText))
        {
            wsData += L"\n\tEvent Message " + wsText;
        }

        if (queryProviderMessageName(wsText))
        {
            wsData += L"\n\tProvider Message Name " + wsText;
        }

        if (queryPropertyCount(&ulData))
        {
            wsData += L"\n\tTotal Property Count ";
            _ultow_s(ulData, arStackBuffer, 10);
            wsData += arStackBuffer;
        }

        if (queryTopLevelPropertyCount(&ulData))
        {
            wsData += L"\n\tTop Level Property Count ";
            _ultow_s(ulData, arStackBuffer, 10);
            wsData += arStackBuffer;

            if (ulData > 0)
            {
                BYTE* pByteInfo = m_traceEventInfo.get();
                const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
                wsData += L"\n\tProperty Names:";
                for (ULONG ulCount = 0; ulCount < ulData; ++ulCount)
                {
                    wsData.append(L"\n\t\t");
                    wsData.append(
                        reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[ulCount].NameOffset));
                    wsData.append(L": ");
                    wsData.append(buildEventPropertyString(ulCount));
                }
            }
        }

        //
        // swap and return
        //
        out_wsString.swap(wsData);
    }

    inline
        void ctEtwRecord::writeFormattedMessage(std::wstring& wsData, bool withDetails) const
    {
        ULONG ulData;
        if (queryTopLevelPropertyCount(&ulData) && (ulData > 0))
        {
            BYTE* pByteInfo = m_traceEventInfo.get();
            const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());

            std::wstring wsProperties;
            std::vector<std::wstring> wsPropertyVector;
            for (ULONG ulCount = 0; ulCount < ulData; ++ulCount)
            {
                wsProperties.append(L"\n[");
                wsProperties.append(
                    reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[ulCount].NameOffset));
                wsProperties.append(L"] ");

                // use the mapped string if it's available
                if (m_traceMapping[ulCount].first)
                {
                    wsProperties.append(m_traceMapping[ulCount].first.get());
                    wsPropertyVector.emplace_back(m_traceMapping[ulCount].first.get());
                }
                else
                {
                    auto wsPropertyValue = buildEventPropertyString(ulCount);
                    wsProperties.append(wsPropertyValue);
                    wsPropertyVector.emplace_back(std::move(wsPropertyValue));
                }
            }
            // need an array of wchar_t* to pass to FormatMessage
            std::vector<PWSTR> messageArguments;
            for (auto& wsProperty : wsPropertyVector)
            {
                messageArguments.push_back(wsProperty.data());
            }

            wsData.assign(L"Event Message: ");
            std::wstring wsEventMessage;
            if (queryEventMessage(wsEventMessage))
            {
                WCHAR* formattedMessage;
                if (0 != FormatMessageW(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                    wsEventMessage.c_str(),
                    0,
                    0,
                    reinterpret_cast<PWSTR>(&formattedMessage), // will be allocated from LocalAlloc
                    0,
                    reinterpret_cast<va_list*>(messageArguments.data())))
                {
                    const auto free_message = wil::scope_exit([&] { LocalFree(formattedMessage); });
                    UNREFERENCED_PARAMETER(free_message); // will not dismiss it - it will always free
                    wsData.append(formattedMessage);
                }
                else
                {
                    wsData.append(wsEventMessage);
                }
            }
            if (withDetails)
            {
                wsData.append(L"\nEvent Message Properties:");
                wsData.append(wsProperties);
            }
        }
        else
        {
            wsData.clear();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    //
    //  Comparison operators
    //
    ////////////////////////////////////////////////////////////////////////////////
    inline
        bool ctEtwRecord::operator==(_In_ const ctEtwRecord& inEvent) const
    {
        if (0 != memcmp(&m_eventHeader, &inEvent.m_eventHeader, sizeof(EVENT_HEADER)))
        {
            return false;
        }
        if (0 != memcmp(&m_etwBufferContext, &inEvent.m_etwBufferContext, sizeof(ETW_BUFFER_CONTEXT)))
        {
            return false;
        }
        if (m_bInit != inEvent.m_bInit)
        {
            return false;
        }
        //
        // a deep comparison of the v_eventHeaderExtendedData member
        //
        // can't just do a byte comparison of the structs since the DataPtr member is a raw ptr value
        // - and can be different raw buffers with the same event
        //
        if (m_eventHeaderExtendedData.size() != inEvent.m_eventHeaderExtendedData.size())
        {
            return false;
        }

        auto thisData = m_eventHeaderExtendedData.cbegin();
        const auto thisDataEnd = m_eventHeaderExtendedData.cend();

        auto inEventData = inEvent.m_eventHeaderExtendedData.cbegin();
        const auto inEventDataEnd = inEvent.m_eventHeaderExtendedData.cend();

        for (; (thisData != thisDataEnd) && (inEventData != inEventDataEnd); ++thisData, ++inEventData)
        {
            if (thisData->ExtType != inEventData->ExtType)
            {
                return false;
            }
            if (thisData->DataSize != inEventData->DataSize)
            {
                return false;
            }
            if (0 != memcmp(
                reinterpret_cast<VOID*>(thisData->DataPtr),
                reinterpret_cast<VOID*>(inEventData->DataPtr), thisData->DataSize))
            {
                return false;
            }
        }
        //
        // a deep comparison of the m_traceEventInfo member
        //
        if (m_cbTraceEventInfo != inEvent.m_cbTraceEventInfo)
        {
            return false;
        }
        if (0 != memcmp(m_traceEventInfo.get(), inEvent.m_traceEventInfo.get(), m_cbTraceEventInfo))
        {
            return false;
        }

        return true;
    }

    inline
        bool ctEtwRecord::operator!=(_In_ const ctEtwRecord& inEvent) const
    {
        return !(operator==(inEvent));
    }

    ////////////////////////////////////////////////////////////////////////////////
    //
    //  Accessors for EVENT_HEADER properties
    //
    //  - retrieved from the member variable
    //    EVENT_HEADER eventHeader;
    //
    ////////////////////////////////////////////////////////////////////////////////
    inline ULONG ctEtwRecord::getThreadId() const noexcept
    {
        return m_eventHeader.ThreadId;
    }

    inline ULONG ctEtwRecord::getProcessId() const noexcept
    {
        return m_eventHeader.ProcessId;
    }

    inline LARGE_INTEGER ctEtwRecord::getTimeStamp() const noexcept
    {
        return m_eventHeader.TimeStamp;
    }

    inline GUID ctEtwRecord::getProviderId() const noexcept
    {
        return m_eventHeader.ProviderId;
    }

    inline GUID ctEtwRecord::getActivityId() const noexcept
    {
        return m_eventHeader.ActivityId;
    }

    inline bool ctEtwRecord::queryKernelTime(_Out_ ULONG* outTime) const noexcept
    {
        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_PRIVATE_SESSION) ||
            (m_eventHeader.Flags & EVENT_HEADER_FLAG_NO_CPUTIME))
        {
            return false;
        }

        *outTime = m_eventHeader.KernelTime;
        return true;
    }

    inline

        bool ctEtwRecord::queryUserTime(_Out_ ULONG* outTime) const noexcept
    {
        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_PRIVATE_SESSION) ||
            (m_eventHeader.Flags & EVENT_HEADER_FLAG_NO_CPUTIME))
        {
            return false;
        }

        *outTime = m_eventHeader.UserTime;
        return true;
    }

    inline ULONG64 ctEtwRecord::getProcessorTime() const noexcept
    {
        return m_eventHeader.ProcessorTime;
    }

    ////////////////////////////////////////////////////////////////////////////////
    //
    //  Accessors for EVENT_DESCRIPTOR properties
    //
    //  - retrieved from the member variable
    //    EVENT_HEADER eventHeader.EventDescriptor;
    //
    ////////////////////////////////////////////////////////////////////////////////
    inline USHORT ctEtwRecord::getEventId() const noexcept
    {
        return m_eventHeader.EventDescriptor.Id;
    }
    inline UCHAR ctEtwRecord::getVersion() const noexcept
    {
        return m_eventHeader.EventDescriptor.Version;
    }
    inline UCHAR ctEtwRecord::getChannel() const noexcept
    {
        return m_eventHeader.EventDescriptor.Channel;
    }
    inline UCHAR ctEtwRecord::getLevel() const noexcept
    {
        return m_eventHeader.EventDescriptor.Level;
    }
    inline UCHAR ctEtwRecord::getOpcode() const noexcept
    {
        return m_eventHeader.EventDescriptor.Opcode;
    }
    inline USHORT ctEtwRecord::getTask() const noexcept
    {
        return m_eventHeader.EventDescriptor.Task;
    }
    inline ULONGLONG ctEtwRecord::getKeyword() const noexcept
    {
        return m_eventHeader.EventDescriptor.Keyword;
    }

    ////////////////////////////////////////////////////////////////////////////////
    //
    //  Accessors for ETW_BUFFER_CONTEXT properties
    //
    //  - retrieved from the member variable
    //    ETW_BUFFER_CONTEXT etwBufferContext;
    //
    ////////////////////////////////////////////////////////////////////////////////
    inline UCHAR ctEtwRecord::getProcessorNumber() const noexcept
    {
        return m_etwBufferContext.ProcessorNumber;
    }
    inline UCHAR ctEtwRecord::getAlignment() const noexcept
    {
        return m_etwBufferContext.Alignment;
    }
    inline USHORT ctEtwRecord::getLoggerId() const noexcept
    {
        return m_etwBufferContext.LoggerId;
    }

    ////////////////////////////////////////////////////////////////////////////////
    //
    //  Accessors for EVENT_HEADER_EXTENDED_DATA_ITEM properties
    //
    //  - retrieved from the member variable
    //    std::vector<EVENT_HEADER_EXTENDED_DATA_ITEM> v_eventHeaderExtendedData;
    //
    //  - required to walk the std::vector to determine if the asked-for property
    //    is in any of the data items stored.
    //
    ////////////////////////////////////////////////////////////////////////////////
    inline bool ctEtwRecord::queryRelatedActivityId(_Out_ GUID* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        bool bFoundProperty = false;
        for (const auto& tempItem : m_eventHeaderExtendedData)
        {
            if (tempItem.ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
            {
                assert(tempItem.DataSize == sizeof(EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID));
                const auto* relatedID = reinterpret_cast<EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID*>(tempItem.DataPtr);
                *out = relatedID->RelatedActivityId;
                bFoundProperty = true;
                break;
            }
        }
        return bFoundProperty;
    }

    inline bool ctEtwRecord::querySID(_Out_ std::shared_ptr<BYTE[]>& out_pSID, _Out_ size_t* out) const
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        bool bFoundProperty = false;
        for (const auto& tempItem : m_eventHeaderExtendedData)
        {
            if (tempItem.ExtType == EVENT_HEADER_EXT_TYPE_SID)
            {
                const auto* tempSid = reinterpret_cast<SID*>(tempItem.DataPtr);
                out_pSID.reset(new BYTE[tempItem.DataSize]);
                *out = tempItem.DataSize;
                memcpy_s(
                    out_pSID.get(),
                    tempItem.DataSize,
                    tempSid,
                    *out);
                bFoundProperty = true;
                break;
            }
        }
        return bFoundProperty;
    }

    inline bool ctEtwRecord::queryTerminalSessionId(_Out_ ULONG* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        bool bFoundProperty = false;;
        for (const auto& tempItem : m_eventHeaderExtendedData)
        {
            if (tempItem.ExtType == EVENT_HEADER_EXT_TYPE_TS_ID)
            {
                assert(tempItem.DataSize == sizeof(EVENT_EXTENDED_ITEM_TS_ID));
                const auto* itemTsId =
                    reinterpret_cast<EVENT_EXTENDED_ITEM_TS_ID*>(tempItem.DataPtr);
                *out = itemTsId->SessionId;
                bFoundProperty = true;
                break;
            }
        }
        return bFoundProperty;
    }

    inline bool ctEtwRecord::queryTransactionInstanceId(_Out_ ULONG* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        bool bFoundProperty = false;
        for (const auto& tempItem : m_eventHeaderExtendedData)
        {
            if (tempItem.ExtType == EVENT_HEADER_EXT_TYPE_INSTANCE_INFO)
            {
                assert(tempItem.DataSize == sizeof(EVENT_EXTENDED_ITEM_INSTANCE));
                const auto* instanceInfo =
                    reinterpret_cast<EVENT_EXTENDED_ITEM_INSTANCE*>(tempItem.DataPtr);
                *out = instanceInfo->InstanceId;
                bFoundProperty = true;
                break;
            }
        }

        return bFoundProperty;
    }

    inline bool ctEtwRecord::queryTransactionParentInstanceId(_Out_ ULONG* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        bool bFoundProperty = false;
        for (const auto& tempItem : m_eventHeaderExtendedData)
        {
            if (tempItem.ExtType == EVENT_HEADER_EXT_TYPE_INSTANCE_INFO)
            {
                assert(tempItem.DataSize == sizeof(EVENT_EXTENDED_ITEM_INSTANCE));
                const auto* instanceInfo =
                    reinterpret_cast<EVENT_EXTENDED_ITEM_INSTANCE*>(tempItem.DataPtr);
                *out = instanceInfo->ParentInstanceId;
                bFoundProperty = true;
                break;
            }
        }
        return bFoundProperty;
    }

    inline bool ctEtwRecord::queryTransactionParentGuid(_Out_ GUID* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        bool bFoundProperty = false;
        for (const auto& tempItem : m_eventHeaderExtendedData)
        {
            if (tempItem.ExtType == EVENT_HEADER_EXT_TYPE_INSTANCE_INFO)
            {
                assert(tempItem.DataSize == sizeof(EVENT_EXTENDED_ITEM_INSTANCE));
                const auto* instanceInfo =
                    reinterpret_cast<EVENT_EXTENDED_ITEM_INSTANCE*>(tempItem.DataPtr);
                *out = instanceInfo->ParentGuid;
                bFoundProperty = true;
                break;
            }
        }

        return bFoundProperty;
    }

    inline bool ctEtwRecord::queryProviderGuid(_Out_ GUID* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        *out = pTraceInfo->ProviderGuid;
        return true;
    }

    inline bool ctEtwRecord::queryDecodingSource(_Out_ DECODING_SOURCE* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        *out = pTraceInfo->DecodingSource;
        return true;
    }

    inline bool ctEtwRecord::queryProviderName(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->ProviderNameOffset)
        {
            return false;
        }

        const wchar_t* szProviderName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->ProviderNameOffset);
        out.assign(szProviderName);
        return true;
    }

    inline bool ctEtwRecord::queryLevelName(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->LevelNameOffset)
        {
            return false;
        }

        const wchar_t* szLevelName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->LevelNameOffset);
        out.assign(szLevelName);
        return true;
    }

    inline bool ctEtwRecord::queryChannelName(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->ChannelNameOffset)
        {
            return false;
        }

        const wchar_t* szChannelName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->ChannelNameOffset);
        out.assign(szChannelName);
        return true;
    }

    inline bool ctEtwRecord::queryKeywords(_Out_ std::vector<std::wstring>& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->KeywordsNameOffset)
        {
            return false;
        }

        const wchar_t* szKeyName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->KeywordsNameOffset);

        std::vector<std::wstring> tempKeywords;
        while (*szKeyName != L'\0')
        {
            tempKeywords.emplace_back(szKeyName);
            szKeyName += wcslen(szKeyName) + 1;
        }
        out.swap(tempKeywords);
        return true;
    }

    inline bool ctEtwRecord::queryTaskName(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->TaskNameOffset)
        {
            return false;
        }

        const wchar_t* szTaskName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->TaskNameOffset);
        out.assign(szTaskName);
        return true;
    }

    inline bool ctEtwRecord::queryOpCodeName(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->OpcodeNameOffset)
        {
            return false;
        }

        const wchar_t* szOpCodeName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->OpcodeNameOffset);
        out.assign(szOpCodeName);
        return true;
    }

    inline bool ctEtwRecord::queryEventMessage(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->EventMessageOffset)
        {
            return false;
        }

        const wchar_t* szEventMessage =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->EventMessageOffset);
        out.assign(szEventMessage);
        return true;
    }

    inline bool ctEtwRecord::queryProviderMessageName(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        if (0 == pTraceInfo->ProviderMessageOffset)
        {
            return false;
        }

        const wchar_t* szProviderMessageName =
            reinterpret_cast<wchar_t*>(m_traceEventInfo.get() + pTraceInfo->ProviderMessageOffset);
        out.assign(szProviderMessageName);
        return true;
    }

    inline bool ctEtwRecord::queryPropertyCount(_Out_ ULONG* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        *out = pTraceInfo->PropertyCount;
        return true;
    }

    inline bool ctEtwRecord::queryTopLevelPropertyCount(_Out_ ULONG* out) const noexcept
    {
        *out = {};

        if (!m_bInit)
        {
            return false;
        }

        if ((m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) || !m_traceEventInfo)
        {
            return false;
        }

        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        *out = pTraceInfo->TopLevelPropertyCount;
        return true;
    }

    inline bool ctEtwRecord::queryEventPropertyStringValue(_Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        if (m_eventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY)
        {
            // per the flags, the byte array is a null-terminated string
            out.assign(reinterpret_cast<wchar_t*>(m_traceEventInfo.get()));
            return true;
        }
        return false;
    }

    inline bool ctEtwRecord::queryEventPropertyName(_In_ const ULONG ulIndex, _Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        // immediately fail if no top level property count value or the value is 0
        ULONG ulData = 0;
        if (!queryTopLevelPropertyCount(&ulData) || (0 == ulData))
        {
            return false;
        }

        if (ulIndex >= ulData)
        {
            return false;
        }

        BYTE* pByteInfo = m_traceEventInfo.get();
        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(pByteInfo);
        const wchar_t* szPropertyFound =
            reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[ulIndex].NameOffset);
        out.assign(szPropertyFound);
        return true;
    }

    inline bool ctEtwRecord::queryEventProperty(_In_ PCWSTR szPropertyName, _Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        // immediately fail if no top level property count value or the value is 0
        ULONG ulData = 0;
        if (!queryTopLevelPropertyCount(&ulData) || (0 == ulData))
        {
            return false;
        }

        // iterate through each property name looking for a match
        BYTE* pByteInfo = m_traceEventInfo.get();
        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        for (ULONG ulCount = 0; ulCount < ulData; ++ulCount)
        {
            const wchar_t* szPropertyFound =
                reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[ulCount].NameOffset);
            if (0 == _wcsicmp(szPropertyName, szPropertyFound))
            {
                out.assign(buildEventPropertyString(ulCount));
                return true;
            }
        }
        return false;
    }

    inline bool ctEtwRecord::queryEventProperty(_In_ const ULONG ulIndex, _Out_ std::wstring& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        // immediately fail if no top level property count value or the value is 0 or ulIndex is larger than
        // total number of properties
        ULONG ulData = 0;
        if (!queryTopLevelPropertyCount(&ulData) || (0 == ulData) || (0 == ulIndex) || (ulIndex > ulData))
        {
            return false;
        }
        //
        // get the property value
        BYTE* pByteInfo = m_traceEventInfo.get();
        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        const bool bFoundMatch =
            (nullptr != reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[ulIndex - 1].NameOffset));

        if (bFoundMatch)
        {
            out.assign(buildEventPropertyString(ulIndex - 1));
        }
        return bFoundMatch;
    }

    inline bool ctEtwRecord::queryEventProperty(_In_ PCWSTR szPropertyName, _Out_ ctPropertyPair& out) const
    {
        out = {};

        if (!m_bInit)
        {
            return false;
        }

        // immediately fail if no top level property count value or the value is 0
        ULONG ulData = 0;
        if (!queryTopLevelPropertyCount(&ulData) || (0 == ulData))
        {
            return false;
        }

        // iterate through each property name looking for a match
        bool bFoundMatch = false;
        BYTE* pByteInfo = m_traceEventInfo.get();
        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());

        for (ULONG ulCount = 0; !bFoundMatch && (ulCount < ulData); ++ulCount)
        {
            const wchar_t* szPropertyFound =
                reinterpret_cast<wchar_t*>(pByteInfo + pTraceInfo->EventPropertyInfoArray[ulCount].NameOffset);
            if (0 == _wcsicmp(szPropertyName, szPropertyFound))
            {
                assert(ulCount < m_traceProperties.size());
                if (ulCount < m_traceProperties.size())
                {
                    out = m_traceProperties[ulCount];
                    bFoundMatch = true;
                }
                else
                {
                    //
                    // something is messed up - the properties found didn't match the # of property values
                    // break and exit now
                }
                break;
            }
        }
        return bFoundMatch;
    }

    inline std::wstring ctEtwRecord::buildEventPropertyString(ULONG out) const
    {
        //
        // immediately fail if no top level property count value or the value asked for is out of range
        ULONG ulData = 0;
        if (!queryTopLevelPropertyCount(&ulData) || (out >= ulData))
        {
            throw std::runtime_error("ctEtwRecord - ETW Property value requested is out of range");
        }

        static constexpr unsigned cch_StackBuffer = 100;
        wchar_t arStackBuffer[cch_StackBuffer]{};

        // retrieve the raw property information
        const auto* pTraceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_traceEventInfo.get());
        USHORT propertyOutType = pTraceInfo->EventPropertyInfoArray[out].nonStructType.OutType;
        const ULONG propertySize = m_traceProperties[out].second;
        const BYTE* propertyBuf = m_traceProperties[out].first.get();

        std::wstring wsData;
        // build a string only if the property data > 0 bytes
        if (propertySize > 0)
        {
            //
            // build the string based on the IN and OUT types
            switch (pTraceInfo->EventPropertyInfoArray[out].nonStructType.InType)
            {
            case TDH_INTYPE_NULL:
            {
                wsData = L"null";
                break;
            }

            case TDH_INTYPE_UNICODESTRING:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_STRING;
                }
                // xs:string
                assert(propertyOutType == TDH_OUTTYPE_STRING);
                // - not guaranteed to be NULL terminated
                const auto* wszBuffer = reinterpret_cast<const wchar_t*>(propertyBuf);
                const wchar_t* wszBufferEnd = wszBuffer + (propertySize / 2);
                // don't assign over the final NULL terminator (will embed the null in the std::wstring)
                while ((wszBuffer < wszBufferEnd) && (L'\0' == *(wszBufferEnd - 1)))
                {
                    --wszBufferEnd;
                }
                wsData.assign(wszBuffer, wszBufferEnd);
                break;
            }

            case TDH_INTYPE_ANSISTRING:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_STRING;
                }
                // xs:string
                assert(propertyOutType == TDH_OUTTYPE_STRING);
                // - not guaranteed to be NULL terminated
                const char* szBuffer = reinterpret_cast<const char*>(propertyBuf);
                const char* szBufferEnd = szBuffer + propertySize;
                // don't assign over the final NULL terminator (will embed the null in the std::wstring)
                while ((szBuffer < szBufferEnd) && (L'\0' == *(szBufferEnd - 1)))
                {
                    --szBufferEnd;
                }
                std::string sData(szBuffer, szBufferEnd);
                // convert to wide
                int iResult = ::MultiByteToWideChar(CP_ACP, 0, sData.c_str(), -1, nullptr, 0);
                if (iResult != 0)
                {
                    std::vector<wchar_t> vszprop(iResult, L'\0');
                    iResult = ::MultiByteToWideChar(CP_ACP, 0, sData.c_str(), -1, vszprop.data(), iResult);
                    if (iResult != 0)
                    {
                        wsData = vszprop.data();
                    }
                }
                break;
            }

            case TDH_INTYPE_INT8:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_BYTE;
                }
                // xs:byte
                assert(1 == propertySize);
                const auto cprop = *(reinterpret_cast<const char*>(propertyBuf));
                assert(propertyOutType == TDH_OUTTYPE_BYTE);
                _itow_s(cprop, arStackBuffer, 10);
                wsData = arStackBuffer;
                break;
            }

            case TDH_INTYPE_UINT8:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_UNSIGNEDBYTE;
                }
                // xs:unsignedByte; win:hexInt8
                assert(1 == propertySize);
                const auto ucprop = *propertyBuf;
                if (TDH_OUTTYPE_UNSIGNEDBYTE == propertyOutType)
                {
                    _itow_s(ucprop, arStackBuffer, 10);
                    wsData = arStackBuffer;
                }
                else if (TDH_OUTTYPE_HEXINT8 == propertyOutType)
                {
                    _itow_s(ucprop, arStackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                else if (TDH_OUTTYPE_BOOLEAN == propertyOutType)
                {
                    if (ucprop == 0)
                    {
                        wsData = L"false";
                    }
                    else
                    {
                        wsData = L"true";
                    }
                }
                else
                {
                    assert(!"Unknown OUT type for TDH_INTYPE_UINT8" && propertyOutType);
                }
                break;
            }

            case TDH_INTYPE_INT16:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_SHORT;
                }
                // xs:short
                assert(2 == propertySize);
                const auto sprop = *(reinterpret_cast<const short*>(propertyBuf));
                assert(propertyOutType == TDH_OUTTYPE_SHORT);
                _itow_s(sprop, arStackBuffer, 10);
                wsData = arStackBuffer;
                break;
            }

            case TDH_INTYPE_UINT16:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_UNSIGNEDSHORT;
                }
                // xs:unsignedShort; win:Port; win:HexInt16
                assert(2 == propertySize);
                const auto usprop = *(reinterpret_cast<const unsigned short*>(propertyBuf));
                if (TDH_OUTTYPE_UNSIGNEDSHORT == propertyOutType)
                {
                    _itow_s(usprop, arStackBuffer, 10);
                    wsData = arStackBuffer;
                }
                else if (TDH_OUTTYPE_PORT == propertyOutType)
                {
                    _itow_s(::ntohs(usprop), arStackBuffer, 10);
                    wsData = arStackBuffer;
                }
                else if (TDH_OUTTYPE_HEXINT16 == propertyOutType)
                {
                    _itow_s(usprop, arStackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                else
                {
                    assert(!"Unknown OUT type for TDH_INTYPE_UINT16" && propertyOutType);
                }
                break;
            }

            case TDH_INTYPE_INT32:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_INT;
                }
                // xs:int
                assert(4 == propertySize);
                const auto iprop = *(reinterpret_cast<const int*>(propertyBuf));
                assert(propertyOutType == TDH_OUTTYPE_INT);
                _itow_s(iprop, arStackBuffer, 10);
                wsData = arStackBuffer;
                break;
            }

            case TDH_INTYPE_UINT32:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_UNSIGNEDINT;
                }
                // xs:unsignedInt, win:PID, win:TID, win:IPv4, win:ETWTIME, win:ErrorCode, win:HexInt32
                assert(4 == propertySize);
                const auto uiprop = *(reinterpret_cast<const unsigned int*>(propertyBuf));
                if ((TDH_OUTTYPE_UNSIGNEDINT == propertyOutType) ||
                    (TDH_OUTTYPE_UNSIGNEDLONG == propertyOutType) ||
                    (TDH_OUTTYPE_PID == propertyOutType) ||
                    (TDH_OUTTYPE_TID == propertyOutType) ||
                    (TDH_OUTTYPE_ETWTIME == propertyOutType))
                {
                    // display as an unsigned int
                    _ultow_s(uiprop, arStackBuffer, 10);
                    wsData = arStackBuffer;
                }
                else if (TDH_OUTTYPE_IPV4 == propertyOutType)
                {
                    // display as a v4 address
                    ::RtlIpv4AddressToString(
                        reinterpret_cast<const IN_ADDR*>(propertyBuf),
                        arStackBuffer
                    );
                    wsData += arStackBuffer;
                }
                else if ((TDH_OUTTYPE_HEXINT32 == propertyOutType) ||
                    (TDH_OUTTYPE_ERRORCODE == propertyOutType) ||
                    (TDH_OUTTYPE_WIN32ERROR == propertyOutType) ||
                    (TDH_OUTTYPE_NTSTATUS == propertyOutType) ||
                    (TDH_OUTTYPE_HRESULT == propertyOutType))
                {
                    // display as a hex value
                    _ultow_s(uiprop, arStackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                else
                {
                    FAIL_FAST_MSG(
                        "Unknown TDH_OUTTYPE [%u] for the TDH_INTYPE_UINT32 value [%u]",
                        propertyOutType, uiprop);
                }
                break;
            }

            case TDH_INTYPE_INT64:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_LONG;
                }
                // xs:long
                assert(8 == propertySize);
                const auto i64prop = *(reinterpret_cast<const int64_t*>(propertyBuf));
                assert(propertyOutType == TDH_OUTTYPE_LONG);
                _i64tow_s(i64prop, arStackBuffer, cch_StackBuffer, 10);
                wsData = arStackBuffer;
                break;
            }

            case TDH_INTYPE_UINT64:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_UNSIGNEDLONG;
                }
                // xs:unsignedLong, win:HexInt64
                assert(8 == propertySize);
                const auto ui64prop = *(reinterpret_cast<const uint64_t*>(propertyBuf));
                if (TDH_OUTTYPE_UNSIGNEDLONG == propertyOutType)
                {
                    _ui64tow_s(ui64prop, arStackBuffer, cch_StackBuffer, 10);
                    wsData = arStackBuffer;
                }
                else if (TDH_OUTTYPE_HEXINT64 == propertyOutType)
                {
                    _ui64tow_s(ui64prop, arStackBuffer, cch_StackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                else
                {
                    assert(!"Unknown OUT type for TDH_INTYPE_UINT64" && propertyOutType);
                }
                break;
            }

            case TDH_INTYPE_FLOAT:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_FLOAT;
                }
                assert(propertyOutType == TDH_OUTTYPE_FLOAT);
                // xs:float
                const auto fprop = *(reinterpret_cast<const float*>(propertyBuf));
                swprintf_s(arStackBuffer, cch_StackBuffer, L"%f", fprop);
                wsData += arStackBuffer;
                break;
            }

            case TDH_INTYPE_DOUBLE:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_DOUBLE;
                }
                assert(propertyOutType == TDH_OUTTYPE_DOUBLE);
                // xs:double
                const auto dbprop = *(reinterpret_cast<const double*>(propertyBuf));
                swprintf_s(arStackBuffer, cch_StackBuffer, L"%f", dbprop);
                wsData += arStackBuffer;
                break;
            }

            case TDH_INTYPE_BOOLEAN:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_BOOLEAN;
                }
                // xs:boolean
                assert(propertyOutType == TDH_OUTTYPE_BOOLEAN);
                const auto iprop = *(reinterpret_cast<const int*>(propertyBuf));
                if (0 == iprop)
                {
                    wsData = L"false";
                }
                else
                {
                    wsData = L"true";
                }
                break;
            }

            case TDH_INTYPE_BINARY:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_HEXBINARY;
                }
                // xs:hexBinary, win:IPv6 (16 bytes), win:SocketAddress
                if (TDH_OUTTYPE_HEXBINARY == propertyOutType)
                {
                    wsData = L'[';
                    const BYTE* pbuffer = propertyBuf;
                    for (ULONG ulBits = 0; ulBits < propertySize; ++ulBits)
                    {
                        unsigned char chData = pbuffer[ulBits];
                        _itow_s(chData, arStackBuffer, 16);
                        wsData += arStackBuffer;
                    }
                    wsData += L']';
                }
                else if (TDH_OUTTYPE_IPV6 == propertyOutType)
                {
                    ::RtlIpv6AddressToString(
                        reinterpret_cast<const IN6_ADDR*>(propertyBuf),
                        arStackBuffer
                    );
                    wsData += arStackBuffer;
                }
                else if (TDH_OUTTYPE_SOCKETADDRESS == propertyOutType)
                {
                    DWORD dwSize = cch_StackBuffer;
                    int iReturn =
                        ::WSAAddressToStringW(reinterpret_cast<sockaddr*>(const_cast<BYTE*>(propertyBuf)), propertySize, nullptr,
                            arStackBuffer, &dwSize);
                    if (0 == iReturn)
                    {
                        wsData = arStackBuffer;
                    }
                }
                else
                {
                    assert(!"Unknown OUT type for TDH_INTYPE_BINARY" && propertyOutType);
                }
                break;
            }

            case TDH_INTYPE_GUID:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_GUID;
                }
                // xs:GUID
                assert(TDH_OUTTYPE_GUID == propertyOutType);
                assert(sizeof(GUID) == propertySize);
                if (sizeof(GUID) == propertySize)
                {
                    RPC_WSTR pszGuid = nullptr;
                    RPC_STATUS uuidStatus = ::UuidToString(
                        reinterpret_cast<GUID*>(const_cast<BYTE*>(propertyBuf)),
                        &pszGuid);
                    if (RPC_S_OK == uuidStatus)
                    {
                        wsData = reinterpret_cast<PWSTR>(pszGuid);
                        ::RpcStringFree(&pszGuid);
                    }
                }
                break;
            }

            case TDH_INTYPE_POINTER:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_HEXINT64;
                }
                assert(TDH_OUTTYPE_HEXINT64 == propertyOutType);
                // win:hexInt64
                if (4 == propertySize)
                {
                    const auto usprop = *(reinterpret_cast<const ULONG*>(propertyBuf));
                    _ultow_s(usprop, arStackBuffer, cch_StackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                else if (8 == propertySize)
                {
                    const auto ui64prop = *(reinterpret_cast<const uint64_t*>(propertyBuf));
                    _ui64tow_s(ui64prop, arStackBuffer, cch_StackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                else
                {
                    wprintf(L"TDH_INTYPE_POINTER was called with a %d -size value\n", propertySize);
                }
                break;
            }

            case TDH_INTYPE_FILETIME:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_DATETIME;
                }
                // xs:dateTime
                assert(sizeof(FILETIME) == propertySize);
                if (sizeof(FILETIME) == propertySize)
                {
                    const auto* ft = reinterpret_cast<const FILETIME*>(propertyBuf);
                    LARGE_INTEGER li{};
                    li.LowPart = ft->dwLowDateTime;
                    li.HighPart = static_cast<long>(ft->dwHighDateTime);
                    _ui64tow_s(li.QuadPart, arStackBuffer, cch_StackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                break;
            }

            case TDH_INTYPE_SYSTEMTIME:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_DATETIME;
                }
                assert(sizeof(SYSTEMTIME) == propertySize);
                if (sizeof(SYSTEMTIME) == propertySize)
                {
                    const auto* st = reinterpret_cast<const SYSTEMTIME*>(propertyBuf);
                    _snwprintf_s(
                        arStackBuffer,
                        cch_StackBuffer,
                        99,
                        L"%d/%d/%d - %d:%d:%d::%d",
                        st->wYear, st->wMonth, st->wDay,
                        st->wHour, st->wMinute, st->wSecond, st->wMilliseconds);
                    wsData = arStackBuffer;
                }
                break;
            }

            case TDH_INTYPE_SID:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_STRING;
                }
                //
                // first write out the raw binary
                wsData = L'[';
                const auto* pbuffer = propertyBuf;
                for (ULONG ulBits = 0; ulBits < propertySize; ++ulBits)
                {
                    const auto chData = pbuffer[ulBits];
                    _itow_s(chData, arStackBuffer, 16);
                    wsData += arStackBuffer;
                }
                wsData += L']';

                // now convert if we can to the friendly name
                wchar_t sztemp[1]{};
                const auto* pSid = reinterpret_cast<const SID*>(pbuffer);
                std::shared_ptr<wchar_t[]> szName;
                std::shared_ptr<wchar_t[]> szDomain;
                DWORD cchName = 0;
                DWORD cchDomain = 0;
                SID_NAME_USE sidNameUse;
                if (!::LookupAccountSid(nullptr, const_cast<SID*>(pSid), sztemp, &cchName, sztemp, &cchDomain, &sidNameUse))
                {
                    if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        szName.reset(new wchar_t[cchName]);
                        szDomain.reset(new wchar_t[cchDomain]);
                        if (::LookupAccountSid(nullptr, const_cast<SID*>(pSid), szName.get(), &cchName, szDomain.get(), &cchDomain,
                            &sidNameUse))
                        {
                            wsData += L"  ";
                            wsData += szDomain.get();
                            wsData += L"\\";
                            wsData += szName.get();
                        }
                    }
                }
                break;
            }

            case TDH_INTYPE_HEXINT32:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_HEXINT32;
                }
                if (4 == propertySize)
                {
                    assert(TDH_OUTTYPE_HEXINT32 == propertyOutType);
                    const auto usprop = *(reinterpret_cast<const unsigned short*>(propertyBuf));
                    _itow_s(usprop, arStackBuffer, 10);
                    wsData = arStackBuffer;
                }
                break;
            }

            case TDH_INTYPE_HEXINT64:
            {
                if (propertyOutType == TDH_OUTTYPE_NULL)
                {
                    propertyOutType = TDH_OUTTYPE_HEXINT64;
                }
                if (8 == propertySize)
                {
                    assert(TDH_OUTTYPE_HEXINT64 == propertyOutType);
                    const auto ui64prop = *(reinterpret_cast<const int64_t*>(propertyBuf));
                    _ui64tow_s(ui64prop, arStackBuffer, cch_StackBuffer, 16);
                    wsData = L"0x";
                    wsData += arStackBuffer;
                }
                break;
            }
            } // switch statement
        }
        return wsData;
    }
} // namespace ctl
