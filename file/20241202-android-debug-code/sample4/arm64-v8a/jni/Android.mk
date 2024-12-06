# Android.mk

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# モジュール名の指定 (hello)
LOCAL_MODULE := watchpoint

# ソースファイルの指定
LOCAL_SRC_FILES := watchpoint.cpp

LOCAL_CPPFLAGS := -std=c++17

# ビルドするライブラリタイプ (実行ファイル形式)
include $(BUILD_EXECUTABLE)