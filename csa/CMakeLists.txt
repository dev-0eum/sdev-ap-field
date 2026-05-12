# 1. CMake 최소 버전 설정
cmake_minimum_required(VERSION 3.10)

# 2. 프로젝트 이름 및 정보 설정
project(csa VERSION 1.0)

# 3. C++ 표준 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 4. 소스 파일 목록
set(SOURCES
    csa.cpp
    src/dot11.cpp
    src/mac.cpp
    src/param.cpp
    src/radiotap.cpp
    src/utils.cpp
)

# 5. 헤더 파일 경로 설정
include_directories(include)

# 6. 실행 파일 생성
add_executable(csa ${SOURCES})

# 7. pcap 라이브러리 링크
target_link_libraries(csa pcap)

# 8. Unit Test 빌드 (공유 소스: mac, radiotap, dot11)
set(TEST_SHARED_SOURCES
    src/dot11.cpp
    src/mac.cpp
    src/radiotap.cpp
)

add_executable(unit_test1 Test/unit_test1.cpp ${TEST_SHARED_SOURCES})
target_link_libraries(unit_test1 pcap)

add_executable(unit_test3 Test/unit_test3.cpp ${TEST_SHARED_SOURCES})
target_link_libraries(unit_test3 pcap)
