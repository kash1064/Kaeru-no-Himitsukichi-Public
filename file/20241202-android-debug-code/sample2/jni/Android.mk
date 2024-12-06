# Android.mk

LOCAL_PATH := $(call my-dir)

###########################################################

include $(CLEAR_VARS)

# モジュール名の指定
LOCAL_MODULE := attack_mem

# ソースファイルの指定
LOCAL_SRC_FILES := attack_mem.cpp

LOCAL_CPPFLAGS := -std=c++17

# ビルドするライブラリタイプ (実行ファイル形式)
include $(BUILD_EXECUTABLE)

###########################################################

include $(CLEAR_VARS)

# モジュール名の指定
LOCAL_MODULE := attack_ptrace

# ソースファイルの指定
LOCAL_SRC_FILES := attack_ptrace.cpp

LOCAL_CPPFLAGS := -std=c++17

# ビルドするライブラリタイプ (実行ファイル形式)
include $(BUILD_EXECUTABLE)

###########################################################

include $(CLEAR_VARS)

# モジュール名の指定
LOCAL_MODULE := attack_vm

# ソースファイルの指定
LOCAL_SRC_FILES := attack_vm.cpp

LOCAL_CPPFLAGS := -std=c++17

# ビルドするライブラリタイプ (実行ファイル形式)
include $(BUILD_EXECUTABLE)

###########################################################