/* Manufacturing

 This example code is in the Public Domain (or CC0 licensed, at your option.)

 Unless required by applicable law or agreed to in writing, this
 software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 CONDITIONS OF ANY KIND, either express or implied.
 */

/* C includes */
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes */
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

/* ESP32 includes */
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <esp_event.h>
#include "esp_timer.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/sens_reg.h"
#include "soc/rtc.h"
#include "driver/gpio.h"
#include "driver/rtc_io.h"
#include "driver/adc.h"
#include "driver/dac.h"
#include "esp_netif.h"
#include <esp_log.h>

#include "wifi_provisioning/manager.h"
#include "wifi_provisioning/scheme_ble.h"
#include "wifi_provisioning/scheme_softap.h"

#include "app_priv.h"
#include "app_event_group.h"
#include "app_oled.h"
#include "aws_iot_core.h"

#define SERV_NAME_PREFIX "PROV_"
#define AP_RECONN_ATTEMPTS 5

/* DECLARATION */
static const char *TAG = "app_main";

/* DEFINITION */
char *concat(const char *s1, const char *s2)
{
	const size_t len1 = strlen(s1);
	const size_t len2 = strlen(s2);
	char *result = malloc(len1 + len2 + 1); // +1 for the null-terminator
	// in real code you would check for errors in malloc here
	memcpy(result, s1, len1);
	memcpy(result + len1, s2, len2 + 1); // +1 to copy the null-terminator
	return result;
}

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id,
						  void *event_data)
{
	static int s_retry_num_ap_not_found = 0;
	static int s_retry_num_ap_auth_fail = 0;

	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
	{
		ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
		esp_wifi_connect();
	}
	else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
	{
		wifi_event_sta_disconnected_t *disconnected =
			(wifi_event_sta_disconnected_t *)event_data;
		xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
		switch (disconnected->reason)
		{
		case WIFI_REASON_AUTH_EXPIRE:
			ESP_LOGW(TAG, "WIFI EVENT : WIFI_REASON_AUTH_EXPIRE");
			break;
		case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
			ESP_LOGW(TAG, "WIFI EVENT : WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT");
			break;
		case WIFI_REASON_BEACON_TIMEOUT:
			ESP_LOGW(TAG, "WIFI EVENT : WIFI_REASON_BEACON_TIMEOUT");
			break;
		case WIFI_REASON_AUTH_FAIL:
			ESP_LOGW(TAG, "WIFI EVENT : WIFI_REASON_AUTH_FAIL");
			break;
		case WIFI_REASON_ASSOC_FAIL:
			ESP_LOGW(TAG, "WIFI EVENT : WIFI_REASON_ASSOC_FAIL");
			break;
		case WIFI_REASON_HANDSHAKE_TIMEOUT:
			ESP_LOGW(TAG, "connect to the AP fail : auth Error");
			if (s_retry_num_ap_auth_fail < AP_RECONN_ATTEMPTS)
			{
				s_retry_num_ap_auth_fail++;
				esp_wifi_connect();
				ESP_LOGI(TAG, "retry connecting to the AP...");
			}
			break;
		case WIFI_REASON_NO_AP_FOUND:
			ESP_LOGW(TAG, "connect to the AP fail : not found");
			if (s_retry_num_ap_not_found < AP_RECONN_ATTEMPTS)
			{
				s_retry_num_ap_not_found++;
				esp_wifi_connect();
				ESP_LOGI(TAG, "retry to connecting to the AP...");
			}
			break;
		default:
			/* None of the expected reasons */
			esp_wifi_connect();
			break;
		}
	}
	else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
	{
		ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		/* Signal main application to continue execution */
		xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
		s_retry_num_ap_not_found = 0;
		s_retry_num_ap_auth_fail = 0;
	}
	else if (event_base == WIFI_PROV_EVENT)
	{
		switch (event_id)
		{
		case WIFI_PROV_START:
			ESP_LOGI(TAG, "Provisioning started");
			break;
		case WIFI_PROV_CRED_RECV:
		{
			wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *)event_data;
			ESP_LOGI(TAG,
					 "Received Wi-Fi credentials"
					 "\n\tSSID     : %s\n\tPassword : %s",
					 (const char *)wifi_sta_cfg->ssid,
					 (const char *)wifi_sta_cfg->password);
			break;
		}
		case WIFI_PROV_CRED_FAIL:
		{
			wifi_prov_sta_fail_reason_t *reason =
				(wifi_prov_sta_fail_reason_t *)event_data;
			ESP_LOGE(TAG,
					 "Provisioning failed!\n\tReason : %s"
					 "\n\tPlease reset to factory and retry provisioning",
					 (*reason == WIFI_PROV_STA_AUTH_ERROR) ? "Wi-Fi station authentication failed" : "Wi-Fi access-point not found");
			break;
		}
		case WIFI_PROV_CRED_SUCCESS:
			ESP_LOGI(TAG, "Provisioning successful");
			break;
		case WIFI_PROV_END:
			/* De-initialize manager once provisioning is finished */
			wifi_prov_mgr_deinit();
			break;
		default:
			break;
		}
	}
}

static void netif_init_sta()
{
	/* Initialize TCP/IP */
	ESP_ERROR_CHECK(esp_netif_init());

	/* Network interface instance shall be explicitly constructed for
	 * the ESP-NETIF to enable its connection to the TCP/IP stack.
	 * For example initialization code for WiFi has to explicitly call esp_netif_create_default_wifi_sta()
	 * after the TCP/IP stack and the event loop have been initialized. */
	esp_netif_create_default_wifi_sta();

	/* Initialize Wi-Fi */
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	/* Set our event handling. See esp_wifi_types.h for WIFI_EVENT.
	 * See esp_netif_types.h for IP_EVENT. */
	ESP_ERROR_CHECK(
		esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
	ESP_ERROR_CHECK(
		esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));
}

static void wifi_init_sta()
{
	/* Start Wi-Fi in station mode with credentials set during provisioning */
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_LOGI(TAG, "wifi_init_sta finished.");

	/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
	EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
										   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
										   pdFALSE,
										   pdFALSE,
										   portMAX_DELAY);

	/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
	if (bits & WIFI_CONNECTED_BIT)
	{
		ESP_LOGI(TAG, "Successfully connected to WIFI");
	}
	else if (bits & WIFI_FAIL_BIT)
	{
		ESP_LOGI(TAG, "Failed to connect to WIFI");
	}
	else
	{
		ESP_LOGE(TAG, "UNEXPECTED EVENT");
	}
}

static void wifi_deinit_sta()
{
	ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler));
	ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler));
	vEventGroupDelete(wifi_event_group);
}

static void get_device_service_name(char *service_name, size_t max)
{
	uint8_t eth_mac[6];
	esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
	snprintf(service_name, max, "%s%02X%02X%02X",
			 SERV_NAME_PREFIX, eth_mac[3], eth_mac[4], eth_mac[5]);
}

void app_main()
{
	esp_log_level_set("app_main",ESP_LOG_INFO);

	/* Create default event loop needed by the
	 * main app and the provisioning service. */
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	/* Initialize app_event_group.h event groups */
	wifi_event_group = xEventGroupCreate();
	mqtt_event_group = xEventGroupCreate();

	app_driver_init();

	/* Initialize NVS partition */
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
	{
		/* NVS partition was truncated
		 * and needs to be erased */
		ret = nvs_flash_erase();

		/* Retry nvs_flash_init */
		ret |= nvs_flash_init();
	}
	if (ret != ESP_OK)
	{
		ESP_LOGE(TAG, "Failed to init NVS");
		return;
	}

	struct timeval;

	/* Device power up */
	ESP_LOGI(TAG, "Device powering up and checking WIFI provision.");
	netif_init_sta();
	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));

	/* Configuration for the provisioning manager */
	wifi_prov_mgr_config_t config = {
		/* What is the Provisioning Scheme that we want ?
		 * wifi_prov_scheme_softap or wifi_prov_scheme_ble */
		.scheme = wifi_prov_scheme_ble,
		/* Any default scheme specific event handler that you would
		 * like to choose. Since our example application requires
		 * neither BT nor BLE, we can choose to release the associated
		 * memory once provisioning is complete, or not needed
		 * (in case when device is already provisioned). Choosing
		 * appropriate scheme specific event handler allows the manager
		 * to take care of this automatically. This can be set to
		 * WIFI_PROV_EVENT_HANDLER_NONE when using wifi_prov_scheme_softap*/
		.scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM};

	/* Initialize provisioning manager with the
		 * configuration parameters set above */
	ESP_ERROR_CHECK(wifi_prov_mgr_init(config));

	bool provisioned = false;
	/* Let's find out if the device is provisioned */
	ESP_ERROR_CHECK(wifi_prov_mgr_is_provisioned(&provisioned));

	/* If device is not yet provisioned start provisioning service */
	if (!provisioned)
	{
		ESP_LOGI(TAG, "Starting provisioning");

		/* What is the Device Service Name that we want
			 * This translates to :
			 *     - Wi-Fi SSID when scheme is wifi_prov_scheme_softap
			 *     - device name when scheme is wifi_prov_scheme_ble
			 */
		char service_name[12];
		get_device_service_name(service_name, sizeof(service_name));

		/* What is the security level that we want (0 or 1):
			 *      - WIFI_PROV_SECURITY_0 is simply plain text communication.
			 *      - WIFI_PROV_SECURITY_1 is secure communication which consists of secure handshake
			 *          using X25519 key exchange and proof of possession (pop) and AES-CTR
			 *          for encryption/decryption of messages.
			 */
		wifi_prov_security_t security = WIFI_PROV_SECURITY_1;

		/* Do we want a proof-of-possession (ignored if Security 0 is selected):
			 *      - this should be a string with length > 0
			 *      - NULL if not used
			 */
		const char *pop = "abcd1234";

		/* What is the service key (could be NULL)
			 * This translates to :
			 *     - Wi-Fi password when scheme is wifi_prov_scheme_softap
			 *     - simply ignored when scheme is wifi_prov_scheme_ble
			 */
		const char *service_key = NULL;

		/* This step is only useful when scheme is wifi_prov_scheme_ble. This will
			 * set a custom 128 bit UUID which will be included in the BLE advertisement
			 * and will correspond to the primary GATT service that provides provisioning
			 * endpoints as GATT characteristics. Each GATT characteristic will be
			 * formed using the primary service UUID as base, with different auto assigned
			 * 12th and 13th bytes (assume counting starts from 0th byte). The client side
			 * applications must identify the endpoints by reading the User Characteristic
			 * Description descriptor (0x2901) for each characteristic, which contains the
			 * endpoint name of the characteristic */
		uint8_t custom_service_uuid[] = {
			/* LSB <---------------------------------------
			 * ---------------------------------------> MSB */
			0x21, 0x43, 0x65, 0x87, 0x09, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab,
			0x90, 0x78, 0x56, 0x34, 0x12};
		wifi_prov_scheme_ble_set_service_uuid(custom_service_uuid);

		/* Start provisioning service */
		ESP_ERROR_CHECK(
			wifi_prov_mgr_start_provisioning(security, pop,
											 service_name, service_key));

		/* Uncomment the following to wait for the provisioning to finish and then release
			 * the resources of the manager. Since in this case de-initialization is triggered
			 * by the configured prov_event_handler(), we don't need to call the following */
		wifi_prov_mgr_wait();
		wifi_prov_mgr_deinit();
	}
	else
	{
		ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi STA");

		/* We don't need the manager as device is already provisioned,
			 * so let's release it's resources */
		wifi_prov_mgr_deinit();
	}

	/* Start Wi-Fi station */
	wifi_init_sta();
	/* Wait for Wi-Fi connection */
	xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, false, true, portMAX_DELAY);
	xEventGroupClearBits(mqtt_event_group, MQTT_SUB_ACK_BIT);

	aws_iot_read_nvs();

    if (xTaskCreate(&thing_shadow_task, "thing_shadow_task", 9216, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Couldn't create cloud task\n");
        /* Indicate error to user */
    }

	char *topic = "iot/#";
	char *message = "not applicable";
	mqtt_payload_t mqttPayload;
	mqttPayload.pTopic = topic;
	mqttPayload.pMessage = message;
	TaskHandle_t xHandle = NULL;
    if (xTaskCreate(&mqtt_sub_task, "mqtt_sub_task", 9216, &mqttPayload, 5, &xHandle) != pdPASS) {
        ESP_LOGE(TAG, "Couldn't create mqtt_sub_task\n");
        /* Indicate error to user */
    }

	xEventGroupWaitBits(mqtt_event_group, MQTT_SUB_ACK_BIT, pdTRUE,pdTRUE,portMAX_DELAY);
	wifi_deinit_sta();

	UBaseType_t uxHighWaterMark = uxTaskGetStackHighWaterMark(NULL);
	ESP_LOGI(TAG, "High WaterMark: %d", uxHighWaterMark);
}
