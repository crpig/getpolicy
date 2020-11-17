LOCAL_PATH:= $(call my-dir)

####################################################################################
# g++ -std=c++11 getpolicy.cpp myext4_crypt.cpp
include $(CLEAR_VARS)
LOCAL_MODULE:= getpolicy
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true
LOCAL_SRC_FILES := getpolicy.cpp myext4_crypt.cpp
LOCAL_CFLAGS := -Werror -Wno-unused-parameter -Wno-sign-compare
LOCAL_C_INCLUDES := \

include $(BUILD_EXECUTABLE)


# g++ -std=c++11 installkey.cpp myKeyUtil.cpp -lcrypto
include $(CLEAR_VARS)
LOCAL_MODULE:= installkey
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true
LOCAL_SRC_FILES := installkey.cpp myKeyUtil.cpp
LOCAL_CFLAGS := -Werror -Wno-unused-parameter -Wno-sign-compare
LOCAL_C_INCLUDES := .
LOCAL_SHARED_LIBRARIES := libcrypto

include $(BUILD_EXECUTABLE)


include $(call all-makefiles-under,$(LOCAL_PATH))