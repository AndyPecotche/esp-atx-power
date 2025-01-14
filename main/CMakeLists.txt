idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "certs/servercert.pem"
                                   "certs/prvtkey.pem")
spiffs_create_partition_image(storage ../data FLASH_IN_PROJECT)