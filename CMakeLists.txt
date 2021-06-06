cmake_minimum_required(VERSION 3.10)
project(password)


set(SOURCES hex.cpp Password.cpp)
add_library(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/headers)
add_subdirectory(pwdgen)
target_link_libraries(${PROJECT_NAME} pwdgen)
set_target_properties(${PROJECT_NAME}
    PROPERTIES
    CXX_STANDARD 17
    CXX_STANDART_REQUIRED TRUE
)