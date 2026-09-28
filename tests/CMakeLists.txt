add_executable(NullSectorGuardTests
    test_main.cpp
)

target_link_libraries(NullSectorGuardTests
    PRIVATE
        NullSectorGuard::NullSectorGuard
)

add_test(NAME NullSectorGuardTests COMMAND NullSectorGuardTests)
