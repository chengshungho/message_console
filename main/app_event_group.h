/*
 * app_event_group.h
 *
 *  Created on: Feb 10, 2020
 *      Author: chrisho
 */

#ifndef APP_EVENT_GROUP_H_
#define APP_EVENT_GROUP_H_
#pragma once

#include <freertos/event_groups.h>

/* Signal Wi-Fi events on this event-group */
EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

EventGroupHandle_t mqtt_event_group;
#define MQTT_CONNECTED_BIT BIT0
#define MQTT_SUB_ACK_BIT BIT1
#define MQTT_PUB_ACK_BIT BIT2

EventGroupHandle_t deep_sleep_event_group;
#define SLEEP_ALLOWED_BIT BIT0

#endif
