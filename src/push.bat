@echo off
adb push ./cmake-build-debug-android-ndk/SilentInjector /data/local/tmp/
adb shell "su -c 'chmod 777 /data/local/tmp/SilentInjector'"