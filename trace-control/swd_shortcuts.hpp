#ifndef SWD_SHORTCUTS_HPP
#define SWD_SHORTCUTS_HPP

#include <xpcc/debug.hpp>
#include "swd/arm_debug.h"

static inline bool str(ARMDebug &tt, uint32_t addr, uint32_t data) {
	XPCC_LOG_DEBUG << "str 0x" << xpcc::hex << addr << xpcc::ascii << " <= 0x" << xpcc::hex << data << xpcc::endl;
	return tt.memStore(addr, data);
}

static inline bool str(ARMDebug &tt, volatile uint32_t* addr, uint32_t data) {
	return str(tt, reinterpret_cast<uint32_t>(addr), data);
}

static inline bool str(ARMDebug &tt, const volatile uint32_t* addr, uint32_t data) {
	return str(tt, reinterpret_cast<uint32_t>(addr), data);
}

#define STR(addr, data) str(tt, addr, data)


static inline uint32_t ldr(ARMDebug &tt, uint32_t addr) {
	uint32_t data;
	tt.memLoad(addr, data);
	XPCC_LOG_DEBUG << "ldr 0x" << xpcc::hex << addr << xpcc::ascii << " => 0x" << xpcc::hex << data << xpcc::endl;
	return data;
}

static inline uint32_t ldr(ARMDebug &tt, volatile uint32_t* addr) {
	return ldr(tt, reinterpret_cast<uint32_t>(addr));
}

static inline uint32_t ldr(ARMDebug &tt, const volatile uint32_t* addr) {
	return ldr(tt, reinterpret_cast<uint32_t>(addr));
}

#define LDR(addr) ldr(tt, addr)

#endif // SWD_SHORTCUTS_HPP
