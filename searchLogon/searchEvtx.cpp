
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <time.h>

#pragma comment(lib,"Wevtapi.lib")
#define ARRAY_SIZE 100
// Print the event as an XML string.


time_t FileTime = 0;
time_t FirstTime = 0;
PWCHAR pIpBuf = 0;
DWORD dwIpBufLength = 0;

PCWCHAR TimeString = L"TimeCreated SystemTime";
PCWCHAR IpAddress = L"IpAddress";

PWCHAR findEnd(PWCHAR pStart) {
    auto pPosEnd = pStart;

    while (*pPosEnd != L'<') {
        pPosEnd++;
    }
    if (pPosEnd == pStart) {
        return 0;
    }
    return pPosEnd;
}

#define WINDOWS_TICK 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL

time_t WindowsTickToUnixSeconds(long long windowsTicks)
{
    return windowsTicks / WINDOWS_TICK - SEC_TO_UNIX_EPOCH;
}

DWORD getCompare(LPWSTR pData) {
    PWCHAR pPos = 0;
    PWCHAR pEnd = 0;
    WCHAR Date[11];
    WCHAR Time[9];
    WCHAR Ip[16];
    time_t unxTime = 0;

    wmemset(Date, 0, 11);
    wmemset(Time, 0, 9);
    wmemset(Ip, 0, 16);

    if (pPos = wcsstr(pData, TimeString)) {
        pPos += wcslen(TimeString) + wcslen(L"=\"");
        wcsncpy(Date, pPos, 10);
        pPos += wcslen(Date) + 1;
        wcsncpy(Time, pPos, 8);

        //std::wcout << L"[DEBUG]" << Date << L" " << Time << std::endl;
    }

    // 时间转 UNIX time
    SYSTEMTIME myTime;
    {
        swscanf(Date, L"%d-%d-%d", &myTime.wYear, &myTime.wMonth, &myTime.wDay);
        swscanf(Time, L"%d:%d:%d", &myTime.wHour, &myTime.wMinute, &myTime.wSecond);
        FILETIME myFileTime;
        SystemTimeToFileTime(&myTime, &myFileTime);
        LARGE_INTEGER li = { 0 };
        li.LowPart = myFileTime.dwLowDateTime;
        li.HighPart = myFileTime.dwHighDateTime;

        long long int hns = li.QuadPart;
        unxTime = WindowsTickToUnixSeconds(hns);
    }

    // 时间对比
    if (unxTime > FileTime) {
        return 0;
    }
    else {
        if (unxTime > FirstTime) {
            FirstTime = unxTime;
            wprintf(L"\n\n%s", pData);
            std::wcout << L"[DEBUG]" << Date << L" " << Time << std::endl;
        }
        else {
            return 0;
        }
    }

    // 获取 IP
    if (pPos = wcsstr(pData, IpAddress)) {
        pPos += wcslen(IpAddress) + wcslen(L"\">");
        pEnd = findEnd(pPos);
        wmemset(Ip, 0, 16);
        wcsncpy(Ip, pPos, pEnd - pPos);
    }
    else {
        
    }

    memset(pIpBuf, 0, dwIpBufLength);
    if (dwIpBufLength < wcslen(Ip)) {
    }
    else {
        wcsncpy(pIpBuf, Ip, pEnd - pPos);
    }

    return 0;
}

DWORD PrintEvent(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    // The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    //wprintf(L"\n\n%s", pRenderedContent);

    getCompare(pRenderedContent);

cleanup:

    if (pRenderedContent)
        free(pRenderedContent);

    return status;
}

// Enumerate all the events in the result set. 
DWORD PrintResults(EVT_HANDLE hResults)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;

    while (true)
    {
        // Get a block of events from the result set.
        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
            if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
            {
                wprintf(L"EvtNext failed with %lu\n", status);
            }

            goto cleanup;
        }

        // For each event, call the PrintEvent function which renders the
        // event for display. PrintEvent is shown in RenderingEvents.
        for (DWORD i = 0; i < dwReturned; i++)
        {
            if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
            {
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else
            {
                goto cleanup;
            }
        }
    }

cleanup:

    // Executed only if there was an error.
    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}

DWORD DumpEvents(LPCWSTR pwsPath)
{
    EVT_HANDLE hResults = NULL;
    DWORD status = ERROR_SUCCESS;
    LPWSTR pQuery = NULL;

    // 日志解析使用 XPATH 语法
    pQuery = (LPWSTR)L"Event/System[EventID=4624] and Event/EventData/Data[@Name='TargetUserName']!='SYSTEM'";

    hResults = EvtQuery(NULL, pwsPath, pQuery, EvtQueryFilePath | EvtQueryReverseDirection);
    //hResults = EvtQuery(NULL, pwsPath, pQuery, EvtQueryFilePath | EvtQueryForwardDirection);
    if (NULL == hResults)
    {
        wprintf(L"EvtQuery failed with %lu.\n", status = GetLastError());
        goto cleanup;
    }

    status = PrintResults(hResults);

cleanup:

    if (hResults)
        EvtClose(hResults);

    return status;
}

DWORD getLatestTimeAndIP(time_t &tFiletime, PWCHAR pBuf, DWORD dwBuflength) {
    FileTime = tFiletime;
    FirstTime = 0;
    pIpBuf = pBuf;
    dwIpBufLength = dwBuflength;

#if 0
    VOID* OldValue;
    if (!Wow64DisableWow64FsRedirection(&OldValue)) {
        std::cout << "[ERROR]Wow64DisableWow64FsRedirection" << std::endl;
    }
#endif 

    DumpEvents(L"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx");

    //DumpEvents(L"C:\\Users\\49894\\Desktop\\Work\\program\\evtx解析\\Debug\\Security.evtx");
    
    tFiletime = FirstTime;

    FileTime = 0;
    FirstTime = 0;
    pIpBuf = 0;
    dwIpBufLength = 0;

    return 0;
}

void test2() {

    time_t testTime = 1582784000;
    WCHAR buf[50];

    getLatestTimeAndIP(testTime, buf, 50);

    std::wcout << L"latest time is " << testTime << std::endl;
    std::wcout << buf << std::endl;
}

