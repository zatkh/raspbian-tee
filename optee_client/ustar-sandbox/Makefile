include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/ustar-sandbox

.PHONY: all ustar-sandbox clean

all: ustar-sandbox
################################################################################
# Teec configuration
################################################################################
PACKAGE_NAME	:= ustar-sandbox

TEES_SRCS	:= main.c \
		   seccomp_demo.c \
		   difc_api.c  \
		   difc_demos.c \
		   difc_mem.c \
		   difc_fl.c \
		   smv_lib.c \
			memdom_lib.c



TEES_SRC_DIR	:= src
TEES_OBJ_DIR	:= $(OUT_DIR)
TEES_OBJS 	:= $(patsubst %.c,$(TEES_OBJ_DIR)/%.o, $(TEES_SRCS))
TEES_INCLUDES 	:= ${CURDIR}/../libteec/include \
		   ${CURDIR}/src \
		   ${CURDIR}/../public \

TEES_CFLAGS	:= $(addprefix -I, $(TEES_INCLUDES)) $(CFLAGS) \
		   -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL) \
		   -DBINARY_PREFIX=\"TEES\" \
		   -DTEE_FS_PARENT_PATH=\"$(CFG_TEE_FS_PARENT_PATH)\" \
		   -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\"

ifeq ($(CFG_GP_SOCKETS),y)
TEES_CFLAGS	+= -DCFG_GP_SOCKETS=1
endif
ifeq ($(RPMB_EMU),1)
TEES_CFLAGS	+= -DRPMB_EMU=1
endif
ifeq ($(CFG_TA_TEST_PATH),y)
TEES_CFLAGS	+= -DCFG_TA_TEST_PATH=1
endif
TEES_FILE	:= $(OUT_DIR)/$(PACKAGE_NAME)
TEES_LFLAGS    := $(LDFLAGS) -L$(OUT_DIR)/../libteec

ifeq ($(CFG_TA_GPROF_SUPPORT),y)
TEES_CFLAGS	+= -DCFG_TA_GPROF_SUPPORT
endif


TEES_LFLAGS	+= -lpthread
# Needed to get clock_gettime() for for glibc versions before 2.17
TEES_LFLAGS	+= -lrt

ustar-sandbox: $(TEES_FILE)

$(TEES_FILE): $(TEES_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -o $@ $+ $(TEES_LFLAGS)
	@echo ""

$(TEES_OBJ_DIR)/%.o: $(TEES_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(TEES_CFLAGS) $(TEES_CFLAGS_$(notdir $<)) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(TEES_OBJS) $(TEES_FILE)
	$(call rmdir,$(OUT_DIR))
