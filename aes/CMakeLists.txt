project (optee_example_aes C)

set (SRC host/main.c)
set (EVIL host/evil.c)

add_executable (${PROJECT_NAME} ${SRC})

add_executable (evil ${EVIL})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)
target_include_directories(evil
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)
target_link_libraries (evil PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (TARGETS evil DESTINATION ${CMAKE_INSTALL_BINDIR})
