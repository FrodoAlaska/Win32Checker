cmake_minimum_required(VERSION 3.27)
project(win32checker)

### Project Variables ###
############################################################
set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(PROJECT_INCLUDES 
  ${PROJECT_INCLUDE_DIR} 
)
############################################################

### CMake Variables ###
############################################################
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
############################################################

### Project Sources ###
############################################################
set(PROJECT_SOURCES 
  ${PROJECT_SRC_DIR}/main.cpp
  ${PROJECT_SRC_DIR}/checker.cpp
)
############################################################

### Final Build ###
############################################################
add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})
############################################################

### Linking ###
############################################################
target_include_directories(${PROJECT_NAME} PUBLIC BEFORE ${PROJECT_INCLUDES})
############################################################

### Compiling Options ###
############################################################
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
############################################################

### Library Install ###
############################################################
install(TARGETS ${PROJECT_NAME} win32checker
        DESTINATION bin)
############################################################
