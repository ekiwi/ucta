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
	// do not initialize the system clock in order to maintin a constant
	// frequency of approx. 16 MHz from the internal RC oscillator
	// switching frequencies disturbes the UART like output from the ETM
	// eventually we need to switch to the synchronous TPIU interface
	// which will provide independence from the system clock of our target controller
	//systemClock::enable();

	asm volatile("": : :"memory");
	uint32_t sorted[10];
	std::memcpy(sorted, values, sizeof(uint32_t) * 10);
	bubble_sort(sorted, 10);
	asm volatile("": : :"memory");

	while (1)
	{
	}

	return 0;
}
