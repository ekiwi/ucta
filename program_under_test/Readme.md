# Program Under Test

This directory contains firmware for the stm32f4 discovery board
which runs the programs that we want to test.
Just copy the `main.cpp` from a trace folder to this
directory, compile and program your development board using
`scons program`.
Now you can use the `trace-control` together with a logic analyzer
to record a trace. You can then use the tools provided in this repository
to analyze the trace you recorded.
