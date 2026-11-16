idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_ota_ops bootloader_support efuse mbedtls
)

