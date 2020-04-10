/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#pragma once

#define JUMPSTART_BOARD_BUTTON_GPIO          5      /* This is the button that is used for toggling the output */
#define JUMPSTART_BOARD_BUTTON_ACTIVE_LEVEL  0
#define JUMPSTART_BOARD_OUTPUT_GPIO          27     /* This is the GPIO on which the output will be set */
/* 
GPIO5  default is input enabled and pullup resistor
GPIO27 default is input enabled and float
*/