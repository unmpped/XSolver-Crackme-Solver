#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>

static int push(wchar_t *out, size_t cap, size_t *at, wchar_t c) {
    if (*at + 1 >= cap) return 0;
    out[(*at)++] = c;
    out[*at] = 0;
    return 1;
}

static int append_quoted(wchar_t *out, size_t cap, size_t *at, const wchar_t *s) {
    if (!push(out, cap, at, L'"')) return 0;
    size_t i = 0;
    while (1) {
        size_t slashes = 0;
        while (s[i] == L'\\') {
            slashes++;
            i++;
        }
        if (!s[i]) {
            for (size_t j = 0; j < slashes * 2; j++) if (!push(out, cap, at, L'\\')) return 0;
            break;
        }
        if (s[i] == L'"') {
            for (size_t j = 0; j < slashes * 2 + 1; j++) if (!push(out, cap, at, L'\\')) return 0;
            if (!push(out, cap, at, L'"')) return 0;
            i++;
        } else {
            for (size_t j = 0; j < slashes; j++) if (!push(out, cap, at, L'\\')) return 0;
            if (!push(out, cap, at, s[i++])) return 0;
        }
    }
    return push(out, cap, at, L'"');
}

int wmain(int argc, wchar_t **argv) {
    wchar_t module[MAX_PATH];
    wchar_t folder[MAX_PATH];
    wchar_t batch[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, module, MAX_PATH);
    if (!length || length >= MAX_PATH) return 2;
    wcscpy(folder, module);
    wchar_t *slash = wcsrchr(folder, L'\\');
    if (!slash) slash = wcsrchr(folder, L'/');
    if (!slash) return 2;
    *slash = 0;
    if (swprintf(batch, MAX_PATH, L"%ls\\launch.bat", folder) < 0) return 2;
    wchar_t params[32768] = L"";
    size_t at = 0;
    for (int i = 1; i < argc; i++) {
        if (i > 1 && !push(params, 32768, &at, L' ')) return 2;
        if (!append_quoted(params, 32768, &at, argv[i])) return 2;
    }
    SHELLEXECUTEINFOW info;
    ZeroMemory(&info, sizeof(info));
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"open";
    info.lpFile = batch;
    info.lpParameters = params;
    info.lpDirectory = folder;
    info.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&info)) {
        fwprintf(stderr, L"Could not start launch.bat (%lu).\n", GetLastError());
        return 3;
    }
    if (info.hProcess) {
        WaitForSingleObject(info.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(info.hProcess, &code);
        CloseHandle(info.hProcess);
        return (int)code;
    }
    return 0;
}
