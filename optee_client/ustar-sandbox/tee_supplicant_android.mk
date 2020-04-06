
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += $(optee_CFLAGS)

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL) \
                -DBINARY_PREFIX=\"TEES\" \
                -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\" \
		-DTEE_FS_PARENT_PATH=\"$(CFG_TEE_FS_PARENT_PATH)\"

ifneq ($(TEEC_TEST_LOAD_PATH),)
LOCAL_CFLAGS += -DTEEC_TEST_LOAD_PATH=\"$(TEEC_TEST_LOAD_PATH)\"
endif

ifeq ($(CFG_TA_TEST_PATH),y)
LOCAL_CFLAGS += -DCFG_TA_TEST_PATH=1
endif

LOCAL_SRC_FILES += src/main.c 



ifeq ($(CFG_TA_GPROF_SUPPORT),y)
LOCAL_CFLAGS += -DCFG_TA_GPROF_SUPPORT
endif

ifeq ($(CFG_TA_FTRACE_SUPPORT),y)
LOCAL_CFLAGS += -DCFG_TA_FTRACE_SUPPORT
endif

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../public \
                    $(LOCAL_PATH)/../libteec/include \
                    $(LOCAL_PATH)/src

LOCAL_SHARED_LIBRARIES := libteec

LOCAL_MODULE := ustar-sandbox
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true
include $(BUILD_EXECUTABLE)
