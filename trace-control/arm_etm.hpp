#ifndef ARM_ETM_HPP
#define ARM_ETM_HPP

#include <xpcc/architecture.hpp>

extern "C" {

typedef struct {
	// source: Embedded Trace Macrocell Architecture Specification
	//         section "3.4 The ETM registers"
	__IOM uint32_t CR; ///< (0x000) Main Control Register
	__IM  uint32_t CCR; ///< (0x001) Configuration Code Register
	__OM  uint32_t TRIGGER; ///< (0x002) Trigger Event Register
	__OM  uint32_t ASICCR; ///< (0x003) ASIC Control Register
	__IOM uint32_t SR; ///< (0x004) Status Register
	__IM  uint32_t SCR; ///< (0x005) System Configuration Register
	__OM  uint32_t TSSCR; ///< (0x006) TraceEnable Start/Stop Control
	__OM  uint32_t TECR2; ///< (0x007) TraceEnable Control 2
	__OM  uint32_t TEEVR; ///< (0x008) TraceEnable Event
	__OM  uint32_t TECR1; ///< (0x009) TraceEnable Control 1
	__OM  uint32_t FFRR; ///< (0x00a) FIFO full region
	__IOM uint32_t FFLR; ///< (0x00b) FIFO full level
	uint32_t NOT_DESCRIBED_YET[0x74];
	__IOM uint32_t TRACEIDR; ///< (0x080) CoreSight Trace ID
	uint32_t NOT_DESCRIBED_YET2[0x36b];
	__IM  uint32_t LAR; ///< (0x3ec) Lock Access Register
	__OM  uint32_t LSR; ///< (0x3ed) Lock Status Register
	__OM  uint32_t AUTHSTATUS; ///< (0x3ee) Authentication Status Register

} ETM_Type;

#define ETM_CR_STALL_PROCESSOR_Pos   7U
#define ETM_CR_STALL_PROCESSOR_Msk  (0x1UL << ETM_CR_STALL_PROCESSOR_Pos)
#define ETM_CR_BRANCH_OUTPUT_Pos     8U
#define ETM_CR_BRANCH_OUTPUT_Msk    (0x1UL << ETM_CR_BRANCH_OUTPUT_Pos)
#define ETM_CR_PROGRAMMING_Pos      10U
#define ETM_CR_PROGRAMMING_Msk      (0x1UL << ETM_CR_PROGRAMMING_Pos)
#define ETM_CR_PORT_SELECTION_Pos   11U
#define ETM_CR_PORT_SELECTION_Msk   (0x1UL << ETM_CR_PORT_SELECTION_Pos)

#define ETM_TECR1_INC_EXC_COTRL_Pos   24U
#define ETM_TECR1_INC_EXC_COTRL_Msk   (0x1UL << ETM_TECR1_INC_EXC_COTRL_Pos)

#define ETM_FFRR_INC_EXC_COTRL_Pos   24U
#define ETM_FFRR_INC_EXC_COTRL_Msk   (0x1UL << ETM_FFRR_INC_EXC_COTRL_Pos)




#define ETM_BASE  (0xE0041000UL) ///< ETM Base Address
#define ETM ((ETM_Type*) ETM_BASE)

}

#endif // ARM_ETM_HPP
