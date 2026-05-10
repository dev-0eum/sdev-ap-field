# 1. CMake 최소 버전 설정
cmake_minimum_required(VERSION 3.10)

# 2. 프로젝트 이름 및 정보 설정
project(csa VERSION 1.0)

# 3. C++ 표준 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 4. 소스 파일 목록
set(SOURCES
    main.cpp
    src/dot11.cpp
    src/mac.cpp
    src/param.cpp
    src/radiotap.cpp
)

# 5. 헤더 파일 경로 설정
include_directories(include)

# 6. 실행 파일 생성
add_executable(csa ${SOURCES})

# 7. pcap 라이브러리 링크
target_link_libraries(csa pcap)
