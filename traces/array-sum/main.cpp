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

using systemClock = SystemClock<ExternalCrystal<MHz8>>;

int
main()
{
	// initialize
	systemClock::enable();
	xpcc::cortex::SysTickTimer::initialize<systemClock>();

	volatile int a[40];

	while (1)
	{
		// enable ETM
		ETM->CR &= ~ETM_CR_PROGRAMMING;
		for(int ii = 0; ii < 40; ++ii) {
			a[ii] += 1;
		}
		// disable ETM
		ETM->CR |= ETM_CR_PROGRAMMING;

		xpcc::delayMilliseconds(1);

	}

	return 0;
}
