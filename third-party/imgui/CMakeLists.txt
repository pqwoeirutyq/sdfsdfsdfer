cmake_minimum_required(VERSION 3.15)

project(imgui)

add_library(${PROJECT_NAME} STATIC
    imgui.cpp
    imgui_draw.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    imgui_demo.cpp
    imgui_impl_win32.cpp
    imgui_impl_dx9.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})