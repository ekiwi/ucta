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


uint32_t fib(uint32_t ii) {
	return (ii > 1)? fib(ii-1) + fib(ii-2) :
	       (ii > 0)? 1 : 0;
}

int
main()
{
	// initialize
	systemClock::enable();
	xpcc::cortex::SysTickTimer::initialize<systemClock>();

	volatile uint32_t result;

	while (1)
	{
		// enable ETM
		ETM->CR &= ~ETM_CR_PROGRAMMING;
		asm volatile("": : :"memory");
		result = fib(10);
		// disable ETM
		asm volatile("": : :"memory");
		ETM->CR |= ETM_CR_PROGRAMMING;
		ITM->PORT[0].u32 = result;

		xpcc::delayMilliseconds(1);

	}

	return 0;
}
