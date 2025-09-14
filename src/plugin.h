#ifndef PLUGIN_H
#define PLUGIN_H

#include "render.h"

#include <kthook/kthook.hpp>

class CPlugin
{
public:
    CPlugin(HMODULE hModule);
    ~CPlugin();

    HMODULE hModule;

private:
    CRender render;

    kthook::kthook_simple<void(__cdecl*)()> hookGameLoop{ reinterpret_cast<void*>(0x561B10) };
    void gameLoop(const decltype(hookGameLoop)& hook);

    kthook::kthook_simple<HRESULT(__stdcall*)(HWND, UINT, WPARAM, LPARAM)> hookWndProc{ reinterpret_cast<void*>(0x747EB0) };
    HRESULT __stdcall onWndProc(const decltype(hookWndProc)& hook, HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
};

#endif // PLUGIN_H