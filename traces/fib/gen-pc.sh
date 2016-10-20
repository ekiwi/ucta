#!/usr/bin/env bash

# use sigrok to interpret the ETM output and extract pc values
sigrok-cli -i trace.sr -P uart:baudrate=8000000:rx=D7,arm_tpiu:stream=10,arm_etmv3 -S uart,arm_tpiu,arm_etmv3 -A arm_etmv3=pc > pc

