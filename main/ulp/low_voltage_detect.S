/* ULP Example: using ADC in deep sleep

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.

   This file contains assembly code which runs on the ULP.

   ULP wakes up to run this code at a certain period, determined by the values
   in SENS_ULP_CP_SLEEP_CYCx_REG registers. On each wake up, the program
   measures input voltage on the given ADC channel 'oversample'
   times. Measurements are accumulated and average value is calculated.
   Average value is compared to the 'low_thr'. If the value is less than 'low_thr',
   ULP wakes up the chip from deep sleep.
*/

/* ULP assembly files are passed through C preprocessor first, so include directives
   and C macros may be used in these files 
 */
#include "soc/rtc_cntl_reg.h"
#include "soc/rtc_io_reg.h"
#include "soc/soc_ulp.h"

    /* ADC1 channel 6, GPIO34 */
    .set adc_channel, 6

    /* Configure the number of ADC samples to average on each measurement.
       For convenience, make it a power of 2. */
    .set oversample_power, 2
    .set oversample, (1 << oversample_power)

    /* Define variables, which go into .bss section (zero-initialized data) */
    .bss

    /* Counter of measurements done */
    .global sample_counter
sample_counter:
	.long 0

    /* Low threshold of ADC reading. Set by the main program. */
    .global low_thr
low_thr:
    .long 0

    /* if voltage < low_thr, Set 1 */
    .global brownout_flag
brownout_flag:
    .long 0

    .global last_result
last_result:
    .long 0

    /* Code goes into .text section */
    .text
    .global entry
entry:
	/* increase sample counter */
	move r3, sample_counter
	ld r2, r3, 0
	add r2, r2, 1
	st r2, r3, 0

    /* initialize r0, r0 will be used as accumulator*/
    move r0, 0
    /* initialize the loop counter */
    stage_rst
measure:
    /* measure and add value to accumulator */
    adc r1, 0, adc_channel + 1
    add r0, r0, r1
    /* increment loop counter and check exit condition */
    stage_inc 1
    jumps measure, oversample, lt

    /* divide accumulator by oversample.
       Since it is chosen as a power of two, use right shift */
    rsh r0, r0, oversample_power
    /* averaged value is now in r0, store it into last result */
    move r3, last_result
    st r0, r3, 0
    /* compare value with low_thr */
    move r3, low_thr
    ld r3, r3, 0
    sub r3, r0, r3
    /* ov - jump if last ALU has set overflow flag
    Jump to wake_up instead low_voltage if r3 = (last_result - low_thr) is negtive (overflow)
    Otherwise the measurement is in valid_voltage range.
    */
    jump wake_up, ov

valid_voltage:
    /* voltage is valid, if brownout happened before wait rwdt to reset chip */

    /* r3 register value = brownout_flag label address */
    //move r3, brownout_flag
    /* load lower 16-bit of a word from memory address r3+0, r0 contains brownout_flag value. */
    //ld r0, r3, 0
    /*jump to feed_dog if value in R0 < 1.  (brownout_flag < 1)
    Feed(reset) watchdog timer before it timeout */
    //jumpr feed_dog, 1, lt
    halt

low_voltage:
    /* set brownout_flag to 1 */
    move r3, brownout_flag
    move r2, 1
    /* set brownout_flag = 1 */
    st r2, r3, 0
    /* power down digital core in sleep */
    //WRITE_RTC_REG(RTC_CNTL_DIG_PWC_REG, RTC_CNTL_DG_WRAP_PD_EN_S, 1, 0)
    /* power down Wi-Fi in sleep */
    //WRITE_RTC_REG(RTC_CNTL_DIG_PWC_REG, RTC_CNTL_WIFI_PD_EN_S, 1, 0)
    /* software stall CPU */
    //WRITE_RTC_REG(RTC_CNTL_SW_CPU_STALL_REG, RTC_CNTL_SW_STALL_PROCPU_C1_S, 6, 0x21)
    //WRITE_RTC_REG(RTC_CNTL_SW_CPU_STALL_REG, RTC_CNTL_SW_STALL_APPCPU_C1_S, 6, 0x21)
    //WRITE_RTC_REG(RTC_CNTL_OPTIONS0_REG, RTC_CNTL_SW_STALL_PROCPU_C0_S, 2, 2)
    //WRITE_RTC_REG(RTC_CNTL_OPTIONS0_REG, RTC_CNTL_SW_STALL_APPCPU_C1_S, 2, 2)
    //jump feed_dog
    jump wake_up

//feed_dog:
    /* Write 0x50d83aa1 to RTC_CNTL_WDTWPROTECT_REG unlock RTC-WDT registers,
    If RTC_CNTL_WDTWPROTECT is other than 0x50d83aa1, then the RTC watchdog will be in
    a write-protected mode and RTC_CNTL_WDTCONFIGn_REG will be locked for modifications.*/
    //WRITE_RTC_REG(RTC_CNTL_WDTWPROTECT_REG, 0, 8, 0xa1)
    //WRITE_RTC_REG(RTC_CNTL_WDTWPROTECT_REG, 8, 8, 0x3a)
    //WRITE_RTC_REG(RTC_CNTL_WDTWPROTECT_REG, 16, 8, 0xd8)
    //WRITE_RTC_REG(RTC_CNTL_WDTWPROTECT_REG, 24, 8, 0x50)
    /* feed RTC-WDT */
    //WRITE_RTC_REG(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED_S, 1, 1)
    /* write any data to lock RTC-WDT registers */
    //WRITE_RTC_REG(RTC_CNTL_WDTWPROTECT_REG, 0, 8, 0)
    //halt
    /* value within range, end the program */

exit:
	/* halts the ULP coprocessor and restarts ULP wakeup timer, if it is enabled */
	halt

wake_up:
	/* Check if the system can be woken up.  Read from a field in rtc_reg into R0 */
	READ_RTC_FIELD(RTC_CNTL_LOW_POWER_ST_REG, RTC_CNTL_RDY_FOR_WAKEUP)
	/* r0 = r0 & 1 */
	and r0, r0, 1
	/* EQ - jump if last ALU operation result was zero.
	If RTC_CNTL_RDY_FOR_WAKEUP = 0 then halt ulp till the SoC is ready for wakeup */
	jump exit, eq

	/* Wake up the SoC, end program */
	wake
	WRITE_RTC_FIELD(RTC_CNTL_STATE0_REG, RTC_CNTL_ULP_CP_SLP_TIMER_EN, 0)
	halt

