file(GLOB_RECURSE PSDK_GTA3_SOURCES "*.cpp" "*.h")
get_target_property(PSDK_SHARED_SOURCES shared SOURCES)

option(PSDK_VER_10EN  ON)
option(PSDK_VER_11EN  OFF)
option(PSDK_VER_STEAM OFF)

add_library(gta3 ${PSDK_GTA3_SOURCES} ${PSDK_SHARED_SOURCES})
add_library(pluginsdk::gta3 ALIAS gta3)
add_dependencies(gta3 shared)

target_link_libraries(gta3 PUBLIC shared)
target_include_directories(gta3
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/plugin_III/;${PROJECT_SOURCE_DIR}/plugin_III/game_III/>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/plugin_III/;${CMAKE_INSTALL_INCLUDEDIR}/plugin_III/game_III/>")
target_compile_definitions(gta3
  PUBLIC
  GTA3
  GTAGAME_NAME="3"
  GTAGAME_ABBR="3"
  GTAGAME_ABBRLOW="3"
  GTAGAME_PROTAGONISTNAME="Claude"
  GTAGAME_CITYNAME="Liberty City"

  $<$<BOOL:${PSDK_VER_10EN}>:PLUGIN_SGV_10EN>
  $<$<BOOL:${PSDK_VER_11EN}>:PLUGIN_SGV_11EN>
  $<$<BOOL:${PSDK_VER_STEAM}>:PLUGIN_SGV_STEAM>)
set_debug_postfix(gta3)

if (PSDK_INSTALL)
  install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/plugin_III/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/plugin_III/
    FILES_MATCHING PATTERN "*.h" PATTERN "*.def")

  install(
    TARGETS gta3
    EXPORT plugin-sdk-targets

    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  )
endif()