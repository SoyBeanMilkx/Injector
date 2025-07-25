cmake_minimum_required(VERSION 3.10)
project(SilentInjector)

set(CMAKE_CXX_STANDARD 17)

# 使用aux_source_directory收集源文件（不递归）
aux_source_directory(. MAIN_SOURCES)
aux_source_directory(core CORE_SOURCES)
aux_source_directory(hide HIDE_SOURCES)
aux_source_directory(utils UTILS_SOURCES)

# 包含目录
include_directories(. core hide utils)

# 查找Android日志库
find_library(log-lib log)

# 创建可执行文件
add_executable(SilentInjector
        ${MAIN_SOURCES}
        ${CORE_SOURCES}
        ${HIDE_SOURCES}
        ${UTILS_SOURCES}
)

# 链接库
target_link_libraries(SilentInjector ${log-lib} dl)