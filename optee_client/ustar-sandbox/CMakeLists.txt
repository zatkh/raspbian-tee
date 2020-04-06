project (ustar-sandbox C)



################################################################################
# Source files
################################################################################
set (SRC
	src/main.c
	src/seccomp_demo.c
	src/difc_api.c 
	src/difc_demos.c
	src/difc_mem.c
	src/difc_fl.c
	src/smv_lib.c
	src/memdom_lib.c




)



################################################################################
# Built binary
################################################################################
add_executable (${PROJECT_NAME} ${SRC})

################################################################################
# Flags always set
################################################################################
target_compile_definitions (${PROJECT_NAME}
	PRIVATE -DCFG_TEE_SUPP_LOG_LEVEL=${CFG_TEE_SUPP_LOG_LEVEL}
	PRIVATE -DTEEC_LOAD_PATH="${CFG_TEE_CLIENT_LOAD_PATH}"
	PRIVATE -DTEE_FS_PARENT_PATH="${CFG_TEE_FS_PARENT_PATH}"
	PRIVATE -DBINARY_PREFIX="TSUP" 
)

add_compile_options (
	-Wno-unused-variable
)


################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries (${PROJECT_NAME}
	PRIVATE teec
	PRIVATE optee-client-headers)

################################################################################
# Install targets
################################################################################
install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
