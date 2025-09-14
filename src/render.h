#ifndef RENDER_H
#define RENDER_H

#include <imgui.h>

#include <kthook/kthook.hpp>

#include <d3d9.h>

class CRender
{
public:
    CRender();
    ~CRender();

    bool toggleMenu();

private:
    bool menu = false;

    void showCursor(bool state);

    std::uintptr_t findDevice(std::uint32_t length);
    void* getFunctionAddress(int VTableIndex);

    kthook::kthook_signal<HRESULT(__stdcall*)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*)> hookPresent{ getFunctionAddress(17) };
    std::optional<HRESULT> onPresent(const decltype(hookPresent)& hook, IDirect3DDevice9* pDevice, const RECT*, const RECT*, HWND, const RGNDATA*);

    kthook::kthook_signal<HRESULT(__stdcall*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*)> hookReset{ getFunctionAddress(16) };
    std::optional<HRESULT> onLost(const decltype(hookReset)& hook, IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* parameters);
    void onReset(const decltype(hookReset)& hook, HRESULT& returnValue, IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* parameters);
};

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif // RENDER_H