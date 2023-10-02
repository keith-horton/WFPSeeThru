// Copyright (C) Microsoft Corporation. All rights reserved.

#include <iostream>
#include <string>
#include <vector>

#include <windows.h>

#include <wil/resource.h>

#include "ctEtwReader.hpp"

using namespace std;
using namespace ctl;

/*
  guid="{C22D1B14-C242-49DE-9F17-1D76B8B9C458}"
  messageFileName="%windir%\system32\drivers\WFPCapture.sys"
  name="Microsoft-Pef-WFP-MessageProvider"
  resourceFileName="%windir%\system32\drivers\WFPCapture.sys"
  symbol="WFP_CAPTURE_PROVIDER"


    // {C82052B6-2B84-4037-A82F-B8CF852122C2}
    TRACELOGGING_DEFINE_PROVIDER(
        g_routePolicyLoggingProvider,
        "WFP.SeeThru.Driver",
        (0xc82052b6, 0x2b84, 0x4037, 0xa8, 0x2f, 0xb8, 0xcf, 0x85, 0x21, 0x22, 0xc2));
*/


constexpr GUID g_wfpCaptureGuid = { 0xC22D1B14, 0xC242, 0x49DE, {0x9F, 0x17, 0x1D, 0x76, 0xB8, 0xB9, 0xC4, 0x58} };
constexpr GUID g_wfpSeeThruDriverGuid = { 0xc82052b6, 0x2b84, 0x4037, {0xa8, 0x2f, 0xb8, 0xcf, 0x85, 0x21, 0x22, 0xc2} };
const pair<GUID, wstring> g_providerListing[]
{
    {g_wfpCaptureGuid, L"WFPCapture"},
    {g_wfpSeeThruDriverGuid, L"WFPSeeThru"},
};

vector<wstring> g_requiredStringValues;

bool ShouldPrintMessage(const wstring& inputString)
{
    bool shouldPrint = true;
    for (const auto& filterStringValue : g_requiredStringValues)
    {
        shouldPrint = false;
        for (size_t offset = 0; filterStringValue.size() <= inputString.size() - offset; ++offset)
        {
            const auto comparisonResults = CompareStringOrdinal(
                &inputString[offset],
                static_cast<int>(filterStringValue.size()),
                filterStringValue.c_str(),
                static_cast<int>(filterStringValue.size()),
                TRUE);
            if (CSTR_EQUAL == comparisonResults)
            {
                shouldPrint = true;
                break;
            }
        }
    }
    return shouldPrint;
}

std::vector<GUID> FindGuidsFromListOfProviders(const wstring& providerName)
{
    std::vector<GUID> returnGuids;
    for (const auto& providerEntry : g_providerListing)
    {
        if (CSTR_EQUAL == CompareStringOrdinal(providerName.c_str(), -1, providerEntry.second.c_str(), -1, TRUE))
        {
            returnGuids.emplace_back(providerEntry.first);
        }
    }

    return returnGuids;
}

struct EventCallback
{
    static std::wstring PrintTime(const ctEtwRecord& record)
    {
        const LARGE_INTEGER timeStamp = record.getTimeStamp();
        FILETIME ft{};
        ft.dwLowDateTime = timeStamp.LowPart;
        ft.dwHighDateTime = timeStamp.HighPart;

        SYSTEMTIME st{};
        THROW_IF_WIN32_BOOL_FALSE(FileTimeToSystemTime(&ft, &st));

        wchar_t rawFriendlyDateTime[24];
        const auto ret = ::_snwprintf_s(
            rawFriendlyDateTime,
            24,
            23, // total size, max chars
            L"%02hu/%02hu/%04hu %02hu:%02hu:%02hu.%03hu",
            st.wMonth,
            st.wDay,
            st.wYear,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
        THROW_HR_IF(E_INVALIDARG, ret != 23);
        return rawFriendlyDateTime;
    }

    void operator()(EVENT_RECORD* const pRecord) const
        try
    {
        const ctEtwRecord record(pRecord);

        wstring provider;
        record.queryProviderName(provider);
        wstring taskName;
        record.queryTaskName(taskName);

        wstring message;
        ULONG propertyCount = 0;
        record.queryPropertyCount(&propertyCount);
        for (ULONG count = 0; count < propertyCount; ++count)
        {
            // the below looks odd - looks like these old ETW classes had an odd index issue
            // querying the property had to start from 1 not 0
            wstring propertyName;
            record.queryEventPropertyName(count, propertyName);
            wstring propertyValue;
            record.queryEventProperty(count + 1, propertyValue);
            message += L" [" + propertyName + L" " + propertyValue + L"]";
        }
        if (ShouldPrintMessage(taskName) || ShouldPrintMessage(message))
        {
            wprintf(L"\n[%ws] %ws : %ws%ws\n", PrintTime(record).c_str(), provider.c_str(), taskName.c_str(),
                message.c_str());
        }
    }
    catch (...)
    {
    }
};

constexpr GUID c_powerEtwSessionGuid = { 0xc99dd1fb, 0x359c, 0x4707, {0xab, 0x16, 0x79, 0x93, 0xeb, 0x2, 0x4a, 0xea} };
ctEtwReader* g_etwReader = nullptr;

BOOL WINAPI ExitFunction(DWORD)
{
    // immediately terminate the process - not flushing queued event records
    if (g_etwReader)
    {
        g_etwReader->StopSession();
    }
    TerminateProcess(GetCurrentProcess(), 0);
    return TRUE;
}

int __cdecl wmain(const int argc, wchar_t** argw)
{
    if (argc == 1)
    {
        return 1;
    }

    SetConsoleCtrlHandler(ExitFunction, TRUE);

    try
    {
        vector<GUID> providers;
        for (int counter = 1; counter < argc; ++counter)
        {
            bool checkArgForProvider = true;
            std::wstring nextArgument{ argw[counter] };
            if (nextArgument.length() > 9) // length of L"-include:"
            {
                if (CompareStringOrdinal(L"-include:", 9, nextArgument.c_str(), 9, TRUE) == CSTR_EQUAL)
                {
                    g_requiredStringValues.emplace_back(nextArgument.substr(9));
                    checkArgForProvider = false;
                }
            }

            if (checkArgForProvider)
            {
                const auto providerGuids = FindGuidsFromListOfProviders(nextArgument);
                if (providerGuids.empty())
                {
                    wprintf(L"Unknown provider : %ws\n", argw[counter]);
                    return 1;
                }
                providers.insert(providers.end(), providerGuids.begin(), providerGuids.end());
            }
        }

        if (!g_requiredStringValues.empty())
        {
            wprintf(L"-> only writing events that include the string%ws",
                g_requiredStringValues.size() > 1 ? L"s" : L"");
            for (const auto& filterString : g_requiredStringValues)
            {
                wprintf(L" '%ws' ", filterString.c_str());
            }
            wprintf(L"\n");
        }
        wprintf(L"Hit Ctrl-C to exit ...\n");

        EventCallback filter{};
        ctEtwReader reader{ filter };
        g_etwReader = &reader;
        reader.StartSession(L"PowerEtwSession", nullptr, c_powerEtwSessionGuid);
        reader.EnableProviders(providers);

        SleepEx(INFINITE, TRUE);
    }
    catch (...)
    {
        return wil::ResultFromCaughtException();
    }

    return 0;
}
