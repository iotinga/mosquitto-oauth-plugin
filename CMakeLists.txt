cmake_minimum_required(VERSION 3.22)

project(mosquitto-oauth-plugin VERSION 1.0)

# Set the output directory for the compiled plugin
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(JANSSON REQUIRED jansson)

add_subdirectory(lib/l8w8jwt)

# Specify the include directories
include_directories(${MOSQUITTO_INCLUDE_DIRS} ${LIBCURL_INCLUDE_DIRS} ${JANSSON_INCLUDE_DIRS} src)

# Specify the source files
file(GLOB SOURCES "src/*.c")

# Create the shared library (plugin)
add_library(${PROJECT_NAME} MODULE ${SOURCES})

target_link_libraries(${PROJECT_NAME} ${MOSQUITTO_LINK_LIBRARIES} ${LIBCURL_LINK_LIBRARIES} ${JANSSON_LINK_LIBRARIES} l8w8jwt)

# Set the shared library version properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""  # Remove the 'lib' prefix
    SUFFIX ".so"  # Ensure the plugin has the .so extension
)

# Install the library
install(TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION lib
)

# Set CMake to use RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
