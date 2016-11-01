#include <xpcc/architecture/platform.hpp>

extern "C" {

typedef struct {
	// source: Embedded Trace Macrocell Architecture Specification
	//         section "3.4 The ETM registers"
	__IOM uint32_t CR; ///< (0x000) Main Control Register
} ETM_Type;

#define ETM_CR_PROGRAMMING (0x1UL << 10U)

#define ETM_BASE  (0xE0041000UL) ///< ETM Base Address
#define ETM ((ETM_Type*) ETM_BASE)

}

void buggy_function(const char* str) {
	char buffer[12];
	std::strcpy(buffer, str);
}

volatile uint32_t counter = 0;

void secret_function() {
	while(1) {
		counter++;
	}
}


volatile int enable_sec = 0;

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

	if(enable_sec) {
		secret_function();
	}

	// 9 characters + '\0'
	buggy_function("012345678");

	// addr: 0x80003a4
	buggy_function("012345678    \xa4\x03\x00\x80");


	while (1)
	{
	}

	return 0;
}
