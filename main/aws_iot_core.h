#ifndef AWS_IOT_CORE_H_
#define AWS_IOT_CORE_H_
#pragma once

typedef struct {
    char *pTopic;
    char *pMessage;
} mqtt_payload_t;

int aws_iot_read_nvs(void);
int aws_thing_shadow_task_start(void);
int aws_mqtt_pub_task_start(void *pJstr);
int aws_mqtt_sub_task_start(void *pJstr);
void thing_shadow_task(void *param);
void mqtt_sub_task(void *param);
void mqtt_pub_task(void *param);

# endif