file(GLOB_RECURSE PSDK_GTAVC_SOURCES "*.cpp" "*.h")
get_target_property(PSDK_SHARED_SOURCES shared SOURCES)

option(PSDK_VER_10EN  ON)
option(PSDK_VER_11EN  OFF)
option(PSDK_VER_STEAM OFF)

add_library(gtavc ${PSDK_GTAVC_SOURCES} ${PSDK_SHARED_SOURCES})
add_library(pluginsdk::gtavc ALIAS gtavc)
add_dependencies(gtavc shared)

target_link_libraries(gtavc PUBLIC shared)
target_include_directories(gtavc
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/plugin_vc/;${PROJECT_SOURCE_DIR}/plugin_vc/game_vc/>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/plugin_vc/;${CMAKE_INSTALL_INCLUDEDIR}/plugin_vc/game_vc/>")
target_compile_definitions(gtavc
  PUBLIC
    GTAVC
    GTAGAME_NAME="Vice City"
    GTAGAME_ABBR="VC"
    GTAGAME_ABBRLOW="vc"
    GTAGAME_PROTAGONISTNAME="Tommy"
    GTAGAME_CITYNAME="Vice City"

    $<$<BOOL:${PSDK_VER_10EN}>:PLUGIN_SGV_10EN>
    $<$<BOOL:${PSDK_VER_11EN}>:PLUGIN_SGV_11EN>
    $<$<BOOL:${PSDK_VER_STEAM}>:PLUGIN_SGV_STEAM>)
set_debug_postfix(gtavc)

if (PSDK_INSTALL)
  install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/plugin_vc/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/plugin_vc/
    FILES_MATCHING PATTERN "*.h" PATTERN "*.def")

  install(
    TARGETS gtavc
    EXPORT plugin-sdk-targets

    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  )
endif()