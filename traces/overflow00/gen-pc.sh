#!/usr/bin/env bash

ELF=target.elf

# use sigrok to interpret the ETM output and extract pc values
sigrok-cli -i trace.sr -P uart:baudrate=16000000:rx=D7,arm_tpiu:stream=10:sync_offset=9,arm_etmv3:branch_enc=original:elffile=$ELF -S uart,arm_tpiu,arm_etmv3 -A arm_etmv3=pc > pc

# please not that this has only been tested with a patched version of
# the sigrok arm_tpiu decoder
# in this version I removed the code that resets the buffer after a
# long silence
