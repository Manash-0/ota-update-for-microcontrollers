idf_component_register(
    SRCS "main.c" "attack_matrix.c" "suit_parser.c"
    INCLUDE_DIRS "."
    REQUIRES esp_ota_ops bootloader_support efuse mbedtls esp_partition
)
