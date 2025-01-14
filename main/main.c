
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "spi_flash_mmap.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_spiffs.h"
#include "driver/gpio.h"
#include <esp_http_server.h>
#include <esp_https_server.h>
#include "esp_tls.h"
#include "protocol_examples_common.h"
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/api.h>
#include <lwip/netdb.h>
#include "sdkconfig.h"
#include "mbedtls/base64.h"
#include "cJSON.h"
#include "esp_mac.h"

/*--------------------- CONFIG THIS SECTION ----------------------*/

#define LED_PIN 2
#define PWR_PIN GPIO_NUM_23
#define RST_PIN GPIO_NUM_22

#define INPUT_PIN GPIO_NUM_22

#define USE_SSL 1

#define AUTH_USERNAME "admin"
#define AUTH_PASSWORD "password"

/*--------------------- -------------------- ----------------------*/

#define INDEX_HTML_PATH "/spiffs/index.html"
static const char *TAG = "WebSocket Server"; // TAG for debug
int led_state = 0;

static void subir_pin(int pin) {
    ESP_LOGI(TAG,"subiendo pin");
    gpio_set_level(pin, 1); // Set pin LOW
    gpio_set_level(LED_PIN, 0); // Turn LED ON
}
static void bajar_pin(int pin) {
    ESP_LOGI(TAG,"bajando pin");
    gpio_set_level(pin, 0); // Set pin LOW
    gpio_set_level(LED_PIN, 1); // Turn LED ON
}


httpd_handle_t server = NULL;
struct async_resp_arg {
    httpd_handle_t hd;
    int fd;
};

char index_html[4096];
char response_data[4096];
static const size_t max_clients = 4;

// Función para enviar un mensaje a todos los clientes conectados
static void enviar_mensaje_clientes(httpd_handle_t server, const char *message) {
    // Crear el paquete WebSocket
    httpd_ws_frame_t ws_pkt = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)message,
        .len = strlen(message)
    };

    // Obtener la lista de clientes conectados
    size_t clients = max_clients;
    int client_fds[max_clients];

    if (httpd_get_client_list(server, &clients, client_fds) == ESP_OK) {
        for (size_t i = 0; i < clients; ++i) {
            int sock = client_fds[i];
            if (httpd_ws_get_fd_info(server, sock) == HTTPD_WS_CLIENT_WEBSOCKET) {
                esp_err_t err = httpd_ws_send_frame_async(server, sock, &ws_pkt);
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "Error sending WebSocket frame to client (fd=%d): %s", sock, esp_err_to_name(err));
                }
            }
        }
    } else {
        ESP_LOGE(TAG, "Failed to get client list!");
    }
}

// Tarea para monitorear el estado del pin INPUT_PIN
static void monitor_input_pin_task(void *arg) {
    httpd_handle_t server = *(httpd_handle_t *)arg; // Pasar el servidor como argumento
    bool last_state = false;
    while (true) {

        bool current_state = gpio_get_level(INPUT_PIN);

        if (current_state != last_state) {
            last_state = current_state;
            const char *message = current_state ? "ON" : "OFF";

            // Enviar mensaje a los clientes conectados
            enviar_mensaje_clientes(server, message);

            ESP_LOGI(TAG, "Pin %d state: %s", INPUT_PIN, message);
        }

        // Esperar 500 ms antes de la siguiente iteración
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}


static esp_err_t check_auth(httpd_req_t *req) {
    size_t buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        char *auth_header = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Authorization", auth_header, buf_len) == ESP_OK) {
            if (strncmp(auth_header, "Basic ", 6) == 0) {
                char *auth_base64 = auth_header + 6;
                size_t output_len;
                unsigned char decoded[64];
                mbedtls_base64_decode(decoded, sizeof(decoded), &output_len, 
                                      (unsigned char *)auth_base64, strlen(auth_base64));
                decoded[output_len] = '\0';

                char expected[64];
                snprintf(expected, sizeof(expected), "%s:%s", AUTH_USERNAME, AUTH_PASSWORD);

                if (strcmp((char *)decoded, expected) == 0) {
                    free(auth_header);
                    return ESP_OK; // Credenciales correctas
                }
            }
        }
        free(auth_header);
    }
    // Si las credenciales son incorrectas o no están presentes
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"WebServer\"");
    return httpd_resp_send(req, "Unauthorized", HTTPD_RESP_USE_STRLEN);
}

static void initi_web_page_buffer(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true};

    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));

    memset((void *)index_html, 0, sizeof(index_html));
    struct stat st;
    if (stat(INDEX_HTML_PATH, &st))
    {
        ESP_LOGE(TAG, "index.html not found");
        return;
    }

    FILE *fp = fopen(INDEX_HTML_PATH, "r");
    if (fread(index_html, st.st_size, 1, fp) == 0)
    {
        ESP_LOGE(TAG, "fread failed");
    }
    fclose(fp);
}


esp_err_t get_req_handler(httpd_req_t *req) {
    if (check_auth(req) != ESP_OK) {
        return ESP_FAIL; // No autenticado, la respuesta ya fue enviada
    }
    return httpd_resp_send(req, index_html, HTTPD_RESP_USE_STRLEN);
}

static void handle_button_action(httpd_req_t *req, gpio_num_t pin, const char *press_msg, const char *rel_msg, int delay_ms) {
    ESP_LOGI(TAG, "Acción sobre el pin %d: %s", pin, press_msg);
    if (pin == RST_PIN) {
        gpio_set_direction(RST_PIN, GPIO_MODE_OUTPUT);
    }
    bajar_pin(pin);

    enviar_mensaje_clientes(server, press_msg);

    vTaskDelay(pdMS_TO_TICKS(delay_ms));
    subir_pin(pin);
    if (pin == RST_PIN) {
        gpio_set_direction(RST_PIN, GPIO_MODE_INPUT);
    }

    enviar_mensaje_clientes(server, rel_msg);
    
    ESP_LOGI(TAG, "Acción completada sobre el pin %d: %s", pin, rel_msg);
}

static esp_err_t handle_ws_req(httpd_req_t *req) {
    if (req->method == HTTP_GET) {
        if (check_auth(req) != ESP_OK) {
           return ESP_FAIL; // No autenticado, la respuesta ya fue enviada
        }
        ESP_LOGI(TAG, "Handshake done, connection opened");
        return ESP_OK;
    }

    // Preparar estructura para el frame WebSocket
    httpd_ws_frame_t ws_pkt = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = NULL,
        .len = 0
    };

    // Recibir tamaño del mensaje
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get WebSocket frame size: %d", ret);
        return ret;
    }

    if (ws_pkt.len > 0) {
        // Reservar memoria para el payload
        char *buf = calloc(1, ws_pkt.len + 1);
        if (!buf) {
            ESP_LOGE(TAG, "Failed to allocate memory for WebSocket payload");
            return ESP_ERR_NO_MEM;
        }

        ws_pkt.payload = (uint8_t *)buf;

        // Recibir el mensaje completo
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to receive WebSocket frame: %d", ret);
            free(buf);
            return ret;
        }

        ESP_LOGI(TAG, "Mensaje recibido: %s", buf);

        // Procesar comandos
        if (strcmp(buf, "PWR") == 0) {
            handle_button_action(req, PWR_PIN, "PWR_PRESS", "PWR_REL", 1000);
        } else if (strcmp(buf, "RST") == 0) {
            handle_button_action(req, RST_PIN, "RST_PRESS", "RST_REL", 1000);
        } else if (strcmp(buf, "FPWR") == 0) {
            handle_button_action(req, PWR_PIN, "PWR_PRESS", "PWR_REL", 4000);
        } else {
            ESP_LOGW(TAG, "Comando no reconocido: %s", buf);
        }

        free(buf);
    }
    return ESP_OK;
}

httpd_handle_t setup_websocket_server(void)
{
    httpd_uri_t uri_get = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = get_req_handler,
        .user_ctx = NULL};

    httpd_uri_t ws = {
        .uri = "/ws",
        .method = HTTP_GET,
        .handler = handle_ws_req,
        .user_ctx = NULL,
        .is_websocket = true};

    if (USE_SSL) {
        httpd_ssl_config_t config_ssl = HTTPD_SSL_CONFIG_DEFAULT();
        extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
        extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
        config_ssl.servercert = servercert_start;
        config_ssl.servercert_len = servercert_end - servercert_start;
        extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
        extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
        config_ssl.prvtkey_pem = prvtkey_pem_start;
        config_ssl.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;
    
        if (httpd_ssl_start(&server, &config_ssl) == ESP_OK)
        {
            httpd_register_uri_handler(server, &uri_get);
            httpd_register_uri_handler(server, &ws);
        }
    }else{
        httpd_config_t config = HTTPD_DEFAULT_CONFIG();
        if (httpd_start(&server, &config) == ESP_OK)
        {
            httpd_register_uri_handler(server, &uri_get);
            httpd_register_uri_handler(server, &ws);
        }
    }
    return server;
}

static esp_err_t stop_webserver(httpd_handle_t server) {
    return httpd_ssl_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop https server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data) {
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        *server = setup_websocket_server();
    }
}


void app_main()
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);


    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    #ifdef CONFIG_EXAMPLE_CONNECT_WIFI
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
    #endif

    #ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
        ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
    #endif

    ESP_ERROR_CHECK(example_connect());

    // Configure GPIO pins

    gpio_set_level(PWR_PIN, 1); // Set default HIGH
    gpio_set_level(RST_PIN, 1); // Set default HIGH
    gpio_set_level(LED_PIN, 0); // LED OFF

    gpio_set_direction(PWR_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(RST_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(INPUT_PIN, GPIO_MODE_INPUT);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);


    led_state = 0;
    ESP_LOGI(TAG, "ESP32 ESP-IDF WebSocket Web Server is running ... ...\n");
    initi_web_page_buffer();
    
    xTaskCreate(monitor_input_pin_task, "monitor_input_pin_task", 4096, &server, 5, NULL);

}
