#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdio.h>

static void quote(wchar_t **out, const wchar_t *arg) {
    *(*out)++ = L'"';
    for (;;) {
        size_t slashes = 0;
        while (*arg == L'\\') { slashes++; arg++; }
        size_t count = (*arg == L'"' || !*arg) ? slashes * 2 : slashes;
        while (count--) *(*out)++ = L'\\';
        if (!*arg) break;
        if (*arg == L'"') *(*out)++ = L'\\';
        *(*out)++ = *arg++;
    }
    *(*out)++ = L'"';
    *(*out)++ = L' ';
}
static BOOL WINAPI console_handler(DWORD type) {
    return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT;
}
int wmain(void) {
    wchar_t module[32768], runtime[32768], script[32768];
    DWORD length = GetModuleFileNameW(NULL, module, 32768);
    if (!length || length >= 32768) return 1;
    wchar_t *end = wcsrchr(module, L'\\');
    if (!end) return 1;
    *end = 0;
    if (_snwprintf_s(runtime, 32768, _TRUNCATE, L"%s\\bun.exe", module) < 0 ||
        _snwprintf_s(script, 32768, _TRUNCATE, L"%s\\..\\Resources\\app\\keyloom-cli.js", module) < 0) return 1;
    if (GetFileAttributesW(runtime) == INVALID_FILE_ATTRIBUTES) {
        if (_snwprintf_s(runtime, 32768, _TRUNCATE, L"%s\\..\\..\\..\\bin\\bun.exe", module) < 0 ||
            _snwprintf_s(script, 32768, _TRUNCATE, L"%s\\..\\keyloom-cli.js", module) < 0) return 1;
    }
    if (GetFileAttributesW(runtime) == INVALID_FILE_ATTRIBUTES || GetFileAttributesW(script) == INVALID_FILE_ATTRIBUTES) {
        fputs("Keyloom runtime is missing. Extract the entire release, not just this launcher.\n", stderr);
        return 1;
    }
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;
    size_t capacity = 2 * (wcslen(runtime) + wcslen(script) + 10);
    for (int i = 1; i < argc; i++) capacity += 2 * wcslen(argv[i]) + 4;
    if (capacity > 32767) { LocalFree(argv); return 2; }
    wchar_t *command = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity * sizeof(wchar_t));
    if (!command) { LocalFree(argv); return 1; }
    wchar_t *cursor = command;
    quote(&cursor, runtime); quote(&cursor, script);
    for (int i = 1; i < argc; i++) quote(&cursor, argv[i]);
    *cursor = 0;
    STARTUPINFOW startup = { 0 };
    PROCESS_INFORMATION process = { 0 };
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    BOOL started = CreateProcessW(runtime, command, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &startup, &process);
    HeapFree(GetProcessHeap(), 0, command); LocalFree(argv);
    if (!started) { fputs("Cannot start Keyloom's bundled Bun runtime.\n", stderr); return 1; }
    SetConsoleCtrlHandler(console_handler, TRUE);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return (int)code;
}
