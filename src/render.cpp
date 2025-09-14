#include "render.h"

#include <imgui_impl_dx9.h>
#include <imgui_impl_win32.h>

kthook::kthook_signal<HWND(__cdecl*)(HINSTANCE)> hookGameInstanceInit{ 0x745560 };

HWND gameHwnd = []()
    {
        HWND* hwndPtr = *reinterpret_cast<HWND**>(0xC17054);

        if (hwndPtr != nullptr)
            return *hwndPtr;
        else
        {
            hookGameInstanceInit.after += [](const auto& hook, HWND& returnValue, HINSTANCE inst)
                {
                    gameHwnd = returnValue;
                };

            return HWND(0);
        }
    }();

CRender::CRender()
{
    using namespace std::placeholders;

    hookPresent.before += std::bind(&CRender::onPresent, this, _1, _2, _3, _4, _5, _6);
    hookPresent.install();

    hookReset.before += std::bind(&CRender::onLost, this, _1, _2, _3);
    hookReset.after += std::bind(&CRender::onReset, this, _1, _2, _3, _4);
    hookReset.install();
}

CRender::~CRender()
{
    if (!ImGui::GetCurrentContext())
        return;

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
}

bool CRender::toggleMenu()
{
    menu = !menu;

    showCursor(menu);
    
    ImGui::GetIO().MouseDrawCursor = menu;

    return menu;
}

void CRender::showCursor(bool state)
{
    static DWORD updateMouseProtection, rsMouseSetPosProtFirst, rsMouseSetPosProtSecond;

    if (state)
    {
        ::VirtualProtect(reinterpret_cast<void*>(0x53F3C6U), 5U, PAGE_EXECUTE_READWRITE, &updateMouseProtection);
        ::VirtualProtect(reinterpret_cast<void*>(0x53E9F1U), 5U, PAGE_EXECUTE_READWRITE, &rsMouseSetPosProtFirst);
        ::VirtualProtect(reinterpret_cast<void*>(0x748A1BU), 5U, PAGE_EXECUTE_READWRITE, &rsMouseSetPosProtSecond);

        *reinterpret_cast<uint8_t*>(0x53F3C6U) = 0xE9U;
        *reinterpret_cast<uint32_t*>(0x53F3C6U + 1U) = 0x15BU;

        memset(reinterpret_cast<void*>(0x53E9F1U), 0x90, 5U);
        memset(reinterpret_cast<void*>(0x748A1BU), 0x90, 5U);
    }
    else
    {
        memcpy(reinterpret_cast<void*>(0x53F3C6U), "\xE8\x95\x6C\x20\x00", 5U);
        memcpy(reinterpret_cast<void*>(0x53E9F1U), "\xE8\xAA\xAA\x0D\x00", 5U);
        memcpy(reinterpret_cast<void*>(0x748A1BU), "\xE8\x80\x0A\xED\xFF", 5U);

        reinterpret_cast<void(__cdecl*)()>(0x541BD0U)();
        reinterpret_cast<void(__cdecl*)()>(0x541DD0U)();

        ::VirtualProtect(reinterpret_cast<void*>(0x53F3C6U), 5U, updateMouseProtection, &updateMouseProtection);
        ::VirtualProtect(reinterpret_cast<void*>(0x53E9F1U), 5U, rsMouseSetPosProtFirst, &rsMouseSetPosProtFirst);
        ::VirtualProtect(reinterpret_cast<void*>(0x748A1BU), 5U, rsMouseSetPosProtSecond, &rsMouseSetPosProtSecond);
    }
}

std::uintptr_t CRender::findDevice(std::uint32_t length)
{
    static std::uintptr_t base = [](std::size_t length)
        {
            std::string pathTo(MAX_PATH, '\0');

            if (auto size = GetSystemDirectoryA(pathTo.data(), MAX_PATH))
            {
                pathTo.resize(size);
                pathTo += "\\d3d9.dll";

                std::uintptr_t dwObjBase = reinterpret_cast<std::uintptr_t>(LoadLibraryA(pathTo.c_str()));

                while (dwObjBase++ < dwObjBase + length)
                {
                    if (*reinterpret_cast<std::uint16_t*>(dwObjBase + 0x00) == 0x06C7 &&
                        *reinterpret_cast<std::uint16_t*>(dwObjBase + 0x06) == 0x8689 &&
                        *reinterpret_cast<std::uint16_t*>(dwObjBase + 0x0C) == 0x8689)
                    {
                        dwObjBase += 2;

                        break;
                    }
                }

                return dwObjBase;
            }

            return std::uintptr_t(0);
        }(length);

    return base;
}

void* CRender::getFunctionAddress(int VTableIndex)
{
    return (*reinterpret_cast<void***>(findDevice(0x128000)))[VTableIndex];
}

std::optional<HRESULT> CRender::onPresent(const decltype(hookPresent)& hook, IDirect3DDevice9* pDevice, const RECT*, const RECT*, HWND, const RGNDATA*)
{
    static bool initialized = false;

    if (!initialized)
    {
        ImGui::CreateContext();

        ImGui_ImplWin32_Init(gameHwnd);
        ImGui_ImplDX9_Init(pDevice);

        ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
        ImGui::GetIO().IniFilename = nullptr;

        #pragma warning(push)
        #pragma warning(disable: 4996)
        std::string font = getenv("WINDIR"); font += "\\Fonts\\Arialbd.TTF";
        #pragma warning(pop)

        ImGui::GetIO().Fonts->AddFontFromFileTTF(font.c_str(), 15.f, nullptr, ImGui::GetIO().Fonts->GetGlyphRangesCyrillic());

        initialized = true;
    }

    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();

    ImGui::NewFrame();

    if (menu)
    {
        ImGui::SetNextWindowPos(ImVec2(100.f, 100.f), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(300.f, 300.f), ImGuiCond_FirstUseEver);

        ImGui::Begin("AsiPluginImGui", nullptr);
        {
            ImGui::Text("Text");
        }
        ImGui::End();
    }

    ImGui::EndFrame();
    ImGui::Render();

    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());

    return std::nullopt;
}

std::optional<HRESULT> CRender::onLost(const decltype(hookReset)& hook, IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* parameters)
{
    ImGui_ImplDX9_InvalidateDeviceObjects();

    return std::nullopt;
}

void CRender::onReset(const decltype(hookReset)& hook, HRESULT& returnValue, IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* parameters)
{

}