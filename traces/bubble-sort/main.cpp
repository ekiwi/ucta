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

const uint32_t values[10] = {4, 8, 3, 25, 3, 0, 4, 5, 100, 7549387};

void swap(uint32_t* vv, const int32_t ii, const int32_t jj) {
	const uint32_t tmp = vv[ii];
	vv[ii] = vv[jj];
	vv[jj] = tmp;
}

void bubble_sort(uint32_t* vv, const int32_t count) {
	bool sorted = false;
	while(not sorted) {
		sorted = true;
		for(int32_t ii = 1; ii < count; ++ii) {
			if(vv[ii-1] > vv[ii]) {
				sorted = false;
				swap(vv, ii-1, ii);
			}
		}
	}
}


int
main()
{
	// initialize
	systemClock::enable();

	while (1)
	{
		// send some dummy values to help sigrok decoder
		ITM->PORT[0].u32 = 0;
		xpcc::delayMicroseconds(2);
		ITM->PORT[0].u32 = 0;
		xpcc::delayMicroseconds(2);
		// send inputs
		for(int32_t ii = 0; ii < 10; ++ii) {
			ITM->PORT[0].u32 = values[ii];
			xpcc::delayMicroseconds(2);
		}

		// enable ETM
		ETM->CR &= ~ETM_CR_PROGRAMMING;
		asm volatile("": : :"memory");
		uint32_t sorted[10];
		std::memcpy(sorted, values, sizeof(uint32_t) * 10);
		bubble_sort(sorted, 10);
		asm volatile("": : :"memory");
		// disable ETM
		ETM->CR |= ETM_CR_PROGRAMMING;

		// send outputs
		for(int32_t ii = 0; ii < 10; ++ii) {
			ITM->PORT[0].u32 = sorted[ii];
			xpcc::delayMicroseconds(2);
		}
		// send some dummy values to help sigrok decoder
		ITM->PORT[0].u32 = 0;
		xpcc::delayMicroseconds(2);
		ITM->PORT[0].u32 = 0;
		xpcc::delayMicroseconds(2);

		xpcc::delayMilliseconds(1);

	}

	return 0;
}
