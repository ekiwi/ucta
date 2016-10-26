# trace-control

The `trace-control` firmware is responsible for configuring the trace hardware,
triggering the logic analyzer and restarting the program under test.

The swd code was copied from
[esp8266-arm-swd](https://github.com/scanlime/esp8266-arm-swd)
and is available under MIT license.
The rest of the code is licensed under GPLv3 just like any other file from this project.


## test setup

Currently this code is running on a
[stm32f3 discovery board](http://www.st.com/en/evaluation-tools/stm32f3discovery.html)
connected to a
[stm32f4 discovery board](http://www.st.com/en/evaluation-tools/stm32f4discovery.html)
which is running the program under test.

### connect UART

UART output is available on `GpioA2` @ 115200 baud.

### connect swd target

To connect the stm32f4 discovery board as trace target you need to do the following:

* remove the two jumper close to the `ST-Link`/`DISCOVERY` print to disconnect SWD
  from the on board ST-Link debug adapter
* connect ground: `GND` (stm32f3) to `GND` (stm32f4)
* connect swd clock: `PC6` (stm32f3) to `PA14` (stm32f4)
* connect swd data: `PC7` (stm32f3) to `PA13` (stm32f4)

### connect logic analyzer

To capture the trace you need a high speed logic analyzer with sufficient
on-board memory. I currently use a DSLogic with the latest
[sigrok](http://sigrok.org/)
compiled from git.

You need to connect the following pins to your analyzer:

* `PB3`, the `SWO` trace output pin on the stm32f4 discovery board (which runs your program under test)
* `PC8` on the stm32f3 discovery board running the `trace-control` software;
  this pin is used to trigger the logic analyzer when a new trace is initiated


