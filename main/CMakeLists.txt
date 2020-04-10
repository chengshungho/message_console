set(COMPONENT_SRCS 
	"app_main.c"
	"app_driver.c"
	"ota.c"
	"aws_custom_utils.c"
	"aws_iot_core.c")
# the header files under main will automatically included but not include subdirectory
set(COMPONENT_ADD_INCLUDEDIRS "include")
# Some components won't be automatically included by CMake. Add the components here.
set(COMPONENT_REQUIRES soc nvs_flash ulp wifi_provisioning esp_https_ota button aws-iot-device-sdk-embedded-C ssd1306)
set(JUMPSTART_BOARD "board_esp32_devkitc.h")

register_component()

target_add_binary_data(${COMPONENT_TARGET} "cloud_cfg/server.cert" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "cloud_cfg/github_server.cert" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "cloud_cfg/endpoint.txt" TEXT)

component_compile_options("-DFW_VERSION=\"v1.1\"")
component_compile_options("-DJUMPSTART_BOARD=\"${JUMPSTART_BOARD}\"")

#
# ULP support additions to component makefile.
#
# 1. ULP_APP_NAME must be unique (if multiple components use ULP)
#    Default value, override if necessary:
set(ULP_APP_NAME ulp_${COMPONENT_NAME})
#
# 2. Specify all assembly source files here.
#    Files should be placed into a separate directory (in this case, ulp/),
#    which should not be added to COMPONENT_SRCS.
set(ULP_S_SOURCES "ulp/low_voltage_detect.S")
#
# 3. List all the component source files which include automatically
#    generated ULP export file, $(ULP_APP_NAME).h:
set(ULP_EXP_DEP_SRCS "app_main.c")
#
# 4. Include build rules for ULP program
# End of ULP support additions to component makefile.
#
include($ENV{IDF_PATH}/components/ulp/component_ulp_common.cmake)
