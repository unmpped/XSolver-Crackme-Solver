#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static FILE *sink;

static void emit(const char *kind, HWND hwnd)
{
    char text[512];
    char title[256];
    int len;

    text[0] = 0;
    title[0] = 0;
    SendMessageA(hwnd, WM_GETTEXT, (WPARAM)sizeof(text) - 1, (LPARAM)text);
    GetWindowTextA(hwnd, title, sizeof(title) - 1);
    len = (int)strlen(text);
    if (len == 0 && strlen(title) == 0) {
        return;
    }
    fprintf(sink, "%s\t%s\t%s\n", kind, title, text);
    fflush(sink);
}

static BOOL CALLBACK each_child(HWND hwnd, LPARAM param)
{
    (void)param;
    emit("child", hwnd);
    return TRUE;
}

static BOOL CALLBACK each_window(HWND hwnd, LPARAM param)
{
    (void)param;
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }
    emit("window", hwnd);
    EnumChildWindows(hwnd, each_child, 0);
    return TRUE;
}

int main(int argc, char **argv)
{
    int seconds = argc > 1 ? atoi(argv[1]) : 5;
    const char *path = argc > 2 ? argv[2] : "windows.txt";
    int i;

    sink = fopen(path, "w");
    if (!sink) {
        return 1;
    }
    for (i = 0; i < seconds * 20; i++) {
        EnumWindows(each_window, 0);
        Sleep(50);
    }
    fclose(sink);
    return 0;
}
