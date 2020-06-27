/*
 * cm4-disasm.c
 * Copyright 2020 by Bill Westfield (westfw@yahoo.com)
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cm4-disasm.h"


#define codesample cm0_sample_code
#define sample_base cm0_sample_base


/*
 */
uint16_t *mainaddr;
decoded_t curinst;

/*
 */
void subdecode_im5lmld (uint16_t *addr, uint32_t ins) {
    curinst.rn = (ins >> 3) & 7;
    curinst.rd = ins & 7;
    curinst.immval = (ins >> 6) & 31;
    curinst.hints.immval = 1;
}

void subdecode_rsrmrd (uint16_t *addr, uint32_t ins) {
    curinst.rd = ins & 7;
    curinst.rn = (ins >> 3) & 7;
    curinst.rm = (ins >> 6) & 7;
}

void subdecode_rmrn (uint16_t *addr, uint32_t ins) {
    curinst.rn = ins & 7;
    curinst.rm = (ins >> 3) & 7;
}

void subdecode_im3 (uint16_t *addr, uint32_t ins) {
    curinst.rd = ins & 7;
    curinst.rn = (ins >> 3) & 7;
    curinst.immval = (ins >> 6) & 7;
    curinst.hints.immval = 1;
}

void subdecode_im8 (uint16_t *addr, uint32_t ins) {
    curinst.immval = ins & 0xFF;
    curinst.hints.immval = 1;
    curinst.rd = (ins >> 8) & 7;
}

void subdecode_thumbexpimm (uint16_t *addr, uint32_t ins)
{
    int16_t word1 = ins, word2 = *(addr+1);
    
    uint32_t i = word1 & 0x0400;
    uint32_t imm3 = (word2 & 0x7000) >> 12;
    uint32_t imm8 = word2 & 0xFF;
    uint32_t val;
    
    if (word1 & 0x10) {
	strcpy(curinst.opcodemod, "s");
    }
    if (i==0 && ((imm3&0x4) == 0)) {
	/* duplicated im8 constants */
	switch (imm3) {
	case 0:
	    val = imm8;
	    break;
	case 1:
	    val = (imm8<<16) + imm8;
	    break;
	case 2:
	    val = (imm8<<24) + (imm8<<8);
	    break;
	case 3:
	    val = (imm8<<24) + (imm8<<16) + (imm8<<8) + imm8;;
	    break;
	}
    } else {
	val = ((imm8 & 0x7F) + 0x80)<<24;   // "unrotated" value,
	/* already rotated 8 */
	int shift = imm3*2;
	if (imm8 & 0x80) shift += 1;
	if (i) shift += 16;
	shift -= 8;
	val >>= shift;
    }
    curinst.immval = val;
    curinst.hints.immval = 1;
    curinst.rn = word1 & 0xF;
    curinst.rd = (word2>>8) & 0xF;
}

void subdecode_exp12 (uint16_t *addr, uint32_t ins)
{
    int16_t word1 = ins, word2 = *(addr+1);
    curinst.rn = word1 & 15;
    curinst.immval = word2 & 0xFF;  // imm8
    curinst.immval += (word2 >> 4) & 0x700;  // imm3
    if (word1 & 0x0400)
	curinst.immval += 0x800;  // i
    curinst.hints.immval = 1;
}

void subdecode_imm16 (uint16_t *addr, uint32_t ins)
{
    int16_t word1 = ins, word2 = *(addr+1);
    curinst.immval = word2 & 0xFF;  // imm8
    curinst.immval += (word2 >> 4) & 0x700;  // imm3
    if (word1 & 0x0400)
	curinst.immval += 0x800;  // i
    curinst.immval += (word1 & 15)<<12;   // imm4
    curinst.hints.immval = 1;
}

/*
 * Table A5-1
 * 6bit top-level opcode + some...
 Shift (immediate), add, subtract, move, and compare

 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0
 00oo.ooo opcode
 opcode Instruction
 0000.0xx Logical Shift Left
 0000.1xx Logical Shift Right
 0001.0xx Arithmetic Shift Right

 0001.100 Add register
 0001.101 Subtract register
 0001.110 Add 3-bit immediate
    0001.111 Subtract 3-bit immediate

    0010.0xx Move
    0010.1xx Compare

    0011.0xx Add 8-bit immediate
    0011.1xx Subtract 8-bit immediate
    */

const decode_entry_t table_top[] = {
    { 0xF8, 0, decode_lsl, 0 },
    { 0xF8, 0x08, decode_lsr, 0 },

    { 0xF8, 0x10, decode_asr, 0 },
    { 0xFC, 0x18, decode_addsubr, 0 },

    { 0xF8, 0x20, decode_mov, 0 },
    { 0xF8, 0x28, decode_cmp, 0 },

    { 0xF8, 0x30, decode_addim8, 0 },
    { 0xF8, 0x38, decode_subim8, 0 },

    { 0xFC, 0x40, decode_dp, 0 },
    { 0xFC, 0x42, decode_specdp, 0 },
    { 0xF8, 0x48, decode_ldvpc, 0 },
    
    { 0xF0, 0x50, decode_ldst5, 0 },
    { 0xF0, 0x60, decode_ldst678, 0 },
    { 0xF0, 0x70, decode_ldst678, 0 },
    { 0xF0, 0x80, decode_ldst678, 0 },
    { 0xF0, 0x90, decode_ldst9, 0 },

    { 0xF8, 0xA0, decode_adr, 0 },
    { 0xF8, 0xA8, decode_addsp4, 0 },

    { 0xFE, 0xB4, decode_push, 0 },
    { 0xFE, 0xBC, decode_pop, 0 },
    { 0xF0, 0xB0, decode_cpumisc, 0 },
    
    { 0xF0, 0xC0, decode_multiple, 0 },

    { 0xF0, 0xD0, decode_branchc, 0 },

    { 0xF8, 0xE0, decode_branch, 0 },

    { 0xFC, 0xE8, decode_thumb32, 0 },
    { 0xF0, 0xF0, decode_thumb32, 0 },
    

#if 0
    { 0xF000, 0xB000, decode_cpumisc, 0},


    { 0xFF00, 0xB000, decode_addsubsp,0},
    { 0xFF00, 0xBA00, decode_extend, 0 },
    
    { 0xF000, 0xD000, decode_branchc, 0 },
    { 0xF800, 0xE800, decode_blx, 0 },
    { 0xF800, 0xF800, decode_bl, 0 },
#endif
    {0,0,decode_error,0}
};


void decode_lsl (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "lsl");
    subdecode_im5lmld(addr, ins);
}

void decode_lsr (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "lsr");
    subdecode_im5lmld(addr, ins);
}


void decode_asr (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "asr");
    subdecode_im5lmld(addr, ins);
}

const decode_entry_t table_addsubr[] = {
    { 0x6, 0x00, decode_add_r, 0 },
    { 0x6, 0x02, decode_subr, 0 },
    { 0x6, 0x04, decode_addim3, 0 },
    { 0x6, 0x06, decode_subim3, 0 },
    {0,0,decode_error,0}
};


void decode_addsubr (uint16_t *addr, uint32_t ins) {
    scan_table(addr, ins>>8, table_addsubr);
}

void decode_mov (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "mov");
    subdecode_im8(addr, ins);
}

void decode_cmp (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "cmp");
    subdecode_im8(addr, ins);
}

void decode_addim8 (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "addi");
}

void decode_subim8 (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "subi");
}

void decode_logic (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "logic");
}

void decode_ldvpc (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "ldr");
    subdecode_im8(addr, *addr);
    curinst.immval *= 4;
    curinst.rm = 15;  // PC
}

char * str_16dp[] = { "and",  "eor",  "lsl",  "lsr",
		      "asr",  "adc",  "sbc",  "ror",
		      "tst",  "rsb",  "cmp",  "cmn",
		      "orr",  "mul",  "bic",  "mvn" };

void decode_dp (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, str_16dp[(ins>>6) & 0xF]);
    subdecode_rmrn(addr, ins);
}

void decode_specdp (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "specdp");
}

void decode_ldst (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "ldst");
}


void decode_ldst5 (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "ldst9");
}

void decode_ldst678 (uint16_t *addr, uint32_t ins) {
    subdecode_im5lmld(addr, ins);
    if (ins & 0x800)
	strcat(curinst.opcode, "ldr");
    else
	strcat(curinst.opcode, "str");
    switch ((ins>>8) & 0xF0) {
    case 0x60:
	curinst.immval *= 4;
	break;
    case 0x70:
	curinst.opcodemod[0] = 'b';
	break;
    case 0x80:
	curinst.opcodemod[0] = 'h';
	curinst.immval *= 2;
	break;
    }
}

void decode_ldst9 (uint16_t *addr, uint32_t ins) {
    if (ins & 0x0800)
	strcat(curinst.opcode, "ldr");
    else
	strcat(curinst.opcode, "str");
    strcpy(curinst.opcode, "ldr");
    subdecode_im8(addr, *addr);
    curinst.rm = 13;
}

void decode_adr (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "adr");
}

void decode_addsp4 (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "addsp");
}

void decode_subsp7 (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "subsp7");
}

void decode_multiple (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "lmul");
}

void decode_bcc  (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "bcc");
}

void decode_branchc(uint16_t *addr, uint32_t ins){
    strcpy(curinst.opcode, "branchc");
}

void decode_branch(uint16_t *addr, uint32_t ins){
    strcpy(curinst.opcode, "b.w");
}

void decode_blx(uint16_t *addr, uint32_t ins){
    strcpy(curinst.opcode, "blx");
}

void decode_bprefix(uint16_t *addr, uint32_t ins){
    strcpy(curinst.opcode, "pre");
}
void decode_bl(uint16_t *addr, uint32_t ins){
    strcpy(curinst.opcode, "bl");
}


void decode_add_r(uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "add");
    subdecode_rsrmrd(addr, *addr);
}

void decode_subr(uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "sub");
    subdecode_rsrmrd(addr, *addr);
}
void decode_addim3(uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "add");
    subdecode_im3(addr, *addr);
}

void decode_subim3(uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "sub");
    subdecode_im3(addr, *addr);
}


/*
 */

void decode_addsub (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "lsl");
    subdecode_im5lmld(addr, *addr);
}

void  decode_addsubsp (uint16_t  *addr, uint32_t ins) {
    strcpy(curinst.opcode, "addsubsp");
}

void  decode_extend (uint16_t  *addr, uint32_t ins) {
    strcpy(curinst.opcode, "xtend");
}

void  decode_push (uint16_t  *addr, uint32_t ins) {
    strcpy(curinst.opcode, "push");
    curinst.immval = *addr & 0xFF;
    if (*addr & 0x100)
	curinst.immval |= 1<<14;
    curinst.hints.reglist = 1;
}

void  decode_pop (uint16_t  *addr, uint32_t ins) {
    strcpy(curinst.opcode, "pop");
    curinst.immval = *addr & 0xFF;
    if (*addr & 0x100)
	curinst.immval |= 1<<15;
    curinst.hints.reglist = 1;
}

/* 
 * Miscellaneous 16bit instructions
 */
const decode_entry_t table_cpumisc[] = {
    { 0x7F, 0x33, decode_cps },
    { 0x7C, 0x00, decode_addsp4 },  // add sp, sp, im7
    { 0x7C, 0x04, decode_subsp7 },
    { 0x78, 0x08, decode_cbz },
    { 0x78, 0x18, decode_cbnz },
    { 0x78, 0x48, decode_cbnz },
    { 0x38, 0x08, decode_sxth },
    { 0x38, 0x08, decode_sxtb },
    { 0x38, 0x08, decode_uxth }, 
    { 0x38, 0x08, decode_uxtb },
    { 0x38, 0x08, decode_rev },
    { 0x38, 0x08, decode_rev16 },
    { 0x38, 0x08, decode_revsh },
    { 0x38, 0x08, decode_bkpt },
    { 0x38, 0x08, decode_it },
    { 0x0, 0, decode_error }
};

void decode_cps (uint16_t *addr, uint32_t ins) {
}

void decode_cbz (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "cbz");
    curinst.rn = *addr & 7;
    curinst.immval = (*addr >> 3) & 0x1F;
    if (ins & 0x4)
	curinst.immval += 64;
    curinst.immval *= 2;
    curinst.immval += 4 + sample_base + (uint32_t) (addr-codesample)*2;
    curinst.hints.immval = 1;
}

void decode_cbnz (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "cbnz");
    curinst.rn = *addr & 7;
    curinst.immval = (*addr >> 3) & 0x1F;
    if (ins & 0x4)
	curinst.immval+=64;
    curinst.immval *= 2;
    curinst.immval += 4 + sample_base + (uint32_t) (addr-codesample)*2;
    curinst.hints.immval = 1;
}


void decode_sxth (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "sxth");
}

void decode_sxtb (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "sxtb");
}

void decode_uxth (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "uxth");
}

void decode_uxtb (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "uxtb");
}

void decode_rev (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "rev");
}

void decode_rev16 (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "rev16");
}

void decode_revsh (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "revsh");
}

void decode_bkpt (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "bkpt");
}

void decode_it (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "it");
}

void decode_cpumisc (uint16_t *addr, uint32_t ins) {
    scan_table(addr, *addr >> 5, table_cpumisc);
}

void subdecode_bra24(uint16_t *addr)
{
    uint16_t word1 = *addr;
    uint16_t word2 = *(addr+1);
    uint32_t dest = word2 & 0x7FF;  // 11 bits from 2nd word
    uint32_t s = !!(word1 & 0x40);
    uint32_t j1 = !!(word2 & 0x2000);
    uint32_t j2 = !!(word2 & 0x0800);
    uint32_t i1 = !(j1 ^ s);
    uint32_t i2 = !(j2 ^ s);
    dest |= (word1 & 0x3FF) << 11;  // 10 bits from word 1
    dest |= i2<<21;
    dest |= i1<<22;
    if (s)
	dest |= 0xFF800000;  // Sign extend
    curinst.immval = dest;
    curinst.hints.immval = 1;

}

void decode_bl32 (uint16_t *addr, uint32_t ins)
{
    if (*(addr+1) & 0x8000) {
	strcpy(curinst.opcode, "bl");
	subdecode_bra24(addr);
	curinst.immval *= 2; // instructions are on 2byte boundaries.
	curinst.immval += sample_base + 4 + (uint32_t) (addr-codesample)*2;
	curinst.hints.immval = 1;
    } else {
	decode_more32(addr, ins);
    }
}

/*
 * Branches and Misc Control.
 */
const decode_entry_t table_bra_op1[] = {
    { 0x5, 0x0, decode_b32misc },
    { 0x7, 0x2, decode_undefined32 },
    { 0x5, 0x1, decode_branch32 },
    { 0x5, 0x5, decode_bl32 },
    { 0, 0, decode_more32 }
};

void decode_branch32misc(uint16_t *addr, uint32_t ins)
{
    uint32_t word2 = addr[1];
    if (*addr == 0xF3AF && *(addr+1) == 0x8000) {
	strcpy(curinst.opcode, "nop.w");
	curinst.hints.immval = 0;
    } else {
	scan_table(addr, word2>>12, table_bra_op1);
    }
    mainaddr++;
}

void decode_b32misc (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "b32misc");
}

void decode_undefined32 (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "undef");
}
void decode_branch32(uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "branch32");
}

/*
 * Table A5.3  Thumb32 Instructions
 * 0b111aaBBBBBBBxxxx CXXXXXXXXXXXXXXX, aa != 10
 * word1 Shifted Right 4 bits
 * 0baaBBBBBBB
 */

const decode_entry_t table_thumb32_op01[] = {
    { 0b1100100, 0b0000000, decode_32ldstm }, 
    { 0b1100100, 0b0000100, decode_32ldstx }, 
    { 0b1100000, 0b0100000, decode_32dpshreg }, 
    { 0b1000000, 0b1000000, decode_32coproc }, 
};
const decode_entry_t table_thumb32_op11[] = {
    { 0b1110001, 0b0000000, decode_32st }, 
    { 0b1100111, 0b0000001, decode_32ldb }, 
    { 0b1100111, 0b0000011, decode_32ldh }, 
    { 0b1100111, 0b0000101, decode_32ld }, 
    { 0b1100111, 0b0000111, decode_undefined }, 

    { 0b1110000, 0b0100000, decode_32dpreg }, 
    { 0b1111000, 0b0110000, decode_32multiply }, 
    { 0b1111000, 0b0111000, decode_32lmultiply }, 
    { 0b1000000, 0b1000000, decode_32coproc },
    { 0, 0, decode_more32 }
};

void decode_32ldstm (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32ldstm");
}
void decode_32ldstx (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32ldstx");
}
void decode_32dpshreg (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32dpshreg");
}
const char *str_dpinsti[] = {"addw", 00000, "movw", 00000,
			     00000, "subw", "movt", 00000,
			     "ssat","ssat16", "sbfx","bfi",
			     "usat","usat16", "ubfx",00000 };

void decode_32dpplain (uint16_t *addr, uint32_t ins)
{
    ins >>= 1;
    ins &= 15;
    if (ins == 2 || ins == 6) {
	subdecode_imm16(addr, ins);
    } else {
	subdecode_exp12(addr, ins);
    }
    strcpy(curinst.opcode, str_dpinsti[ins]);
    mainaddr++;  // skip 2nd word.
}
const char *str_dpinstmi[] = {"and", "bic", "orr", "orn",
			      "eor", 00000, 00000, 00000,
			      "add", 00000, "adc", "sbc",
			      00000, "sub", "rsb", 00000 };
const char *str_dpinstmipc[] = {"tst", "bic", "mov.w", "mvn",
				"teq", 00000, 00000, 00000,
				"cmn", 00000, "adc", "sbc",
				00000, "cmp", "rsb", 00000 };
void decode_32dpmod (uint16_t *addr, uint32_t ins)
{
    ins >>= 5;
    ins &= 15;
    subdecode_thumbexpimm(addr, ins);
    if (curinst.rn == 0xF) {
	strcpy(curinst.opcode, str_dpinstmipc[ins]);
	curinst.rn = -1;
    } else {
	strcpy(curinst.opcode, str_dpinstmi[ins]);
    }
    mainaddr++;  // skip 2nd word.
}

void decode_32st (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32st");
}
void decode_32ldb (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32ldb");
}
void decode_32ldh (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32ldh");
}
void decode_32ld (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32ld");
}
void decode_undefined (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "undefined");
}

void decode_32dpreg (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "32dpreg");
}
void decode_32multiply (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "multiply");
}
void decode_32lmultiply (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "lmult");
}
void decode_32coproc (uint16_t *addr, uint32_t ins)
{
    strcpy(curinst.opcode, "coproc");
}

void decode_thumb32 (uint16_t *addr, uint32_t ins) {
    curinst.hints.twowords = 1;
    ins = *addr;
    if ((ins >> 11) == 0b11110) { //op1 = 10
	if (*(addr+1) & 0x8000) { // op set?
	    decode_branch32misc(addr, ins);
	} else {
	    if (ins & 0b0000001000000000) {
		decode_32dpplain(addr, ins);
	    } else {
		decode_32dpmod(addr, ins);
	    }
	}
    } else if ((ins>>11) == 0b11101) {
	scan_table(addr, ins>>4, table_thumb32_op01);
    } else {
	scan_table(addr, ins>>4, table_thumb32_op11);
    }
}

void decode_more32 (uint16_t *addr, uint32_t ins) {
    uint32_t word2 = *(addr+1);
    curinst.immval = word2;
    curinst.hints.immval = 1;
    strcpy(curinst.opcode, "thumb32");
    mainaddr++;
}

void decode_error (uint16_t *addr, uint32_t ins) {
    strcpy(curinst.opcode, "!error!");
}

/*
  0000.0xxx.im5lmld lsl
  0000.1xxx.im5lmk lsr
  0001.0xxx.im5lmkd asr
  0001.1 addsub lmlnld/im3lnld
  0010.0 mov ldim8
  0010.1 cmp ldim8
  0011.0 add ldim8
  0011.1 sub ldim8
  0100.0 logops op lsld
  0100.1 ldr pcim8
  0101.x ld/st
  0110.x ld/st
  0111.x ld/st
  1000.x str
  1001.x st
  1010.0 adr
  1010.1 addspRd
  1011.x misc
  1100.0 stmia
  1100.1 ldmia
  1101.x bcond
  1110.0 b
  1110.1 blx
  1111.0 bpre
  1111.1 bpre

  addsub im3lnld

  addsub ldim8
  andeorlsllsr lmld
  asradcsbcror lmld
  tstnegcmpcmn lmld
  orrmulbicmvn lmld
  mov lmld
*/

int scan_table(uint16_t *addr, uint32_t ins, const decode_entry_t *table)
{
    int i=0;
    const decode_entry_t *d;
    while (1) {
	d = table + i;
	if ((ins & d->mask) == d->val) {
	    (d->func)(addr, *addr);  // revert ins to full instruction
	    return 0;
	}
	i++;
    }
    return 1;
}


uint32_t cm4_sample_base = 0x4264;
uint16_t cm4_sample_code[] = {
    /*           */ 0xb510, 0x4c05, 0x7823, 0xb933, 0x4b04, 0xb113,
    0x4804, 0xf3af, 0x8000, 0x2301, 0x7023, 0xbd10, 0x0100, 0x2000,
    0x0000, 0x0000, 0x6b70, 0x0000, 0xb508, 0x4b03, 0xb11b, 0x4903,
    0x4803, 0xf3af, 0x8000, 0xbd08, 0x0000, 0x0000, 0x0104, 0x2000,
    0x6b70, 0x0000, 0x2101, 0x200d, 0xf000, 0xba06, 0xb508, 0x4b0b,
    0x480b, 0x6819, 0xf000, 0xfa97, 0x2101, 0x200d, 0xf000, 0xfa40,
    0xf44f, 0x707a, 0xf000, 0xf8dc, 0x200d, 0x2100, 0xf000, 0xfa38,
    0xf44f, 0x707a, 0xe8bd, 0x4008, 0xf000, 0xb8d2, 0x0000, 0x2000,
    0x03a8, 0x2000, 0x4801, 0xf001, 0xbd93, 0xbf00, 0x011c, 0x2000,
    0xf7ff, 0xbff8, 0xf7ff, 0xbff6, 0xf7ff, 0xbff4, 0xb513, 0x4912,
    0x4812, 0x4c13, 0xf000, 0xfaa6, 0x4912, 0x4813, 0xf000, 0xfaa2,
    0x4912, 0x4813, 0xf000, 0xfa9e, 0x4912, 0x4620, 0xf000, 0xfa9a,
    0xf04f, 0x4186, 0x4810, 0xf000, 0xfa95, 0x4910, 0x4810, 0xf000,
    0xfa91, 0x2301, 0x2200, 0xe9cd, 0x3200, 0x4621, 0x480d, 0xf001,
    0xfd05, 0xb002, 0xbd10, 0xbf00, 0x3000, 0x4000, 0x0358, 0x2000,
    0x037c, 0x2000, 0x3400, 0x4000, 0x0364, 0x2000, 0x2000, 0x4101,
    0x0370, 0x2000, 0x4000, 0x4101, 0x0388, 0x2000, 0x0400, 0x4300,
    0x0394, 0x2000, 0x011c, 0x2000, 0xe7fe, 0x0000, 0x4b02, 0x681b,
    0xb103, 0x4718, 0x4770, 0xbf00, 0x03a0, 0x2000, 0xb508, 0x4915,
    0x4b15, 0x428b, 0xd10f, 0x4a15, 0xf8d2, 0x3088, 0xf443, 0x0370,
    0xf8c2, 0x3088, 0xf3bf, 0x8f4f, 0xf3bf, 0x8f6f, 0xf000, 0xf888,
    0xf001, 0xfe0c, 0xe7fe, 0x4a0e, 0x429a, 0xd0ec, 0x428b, 0x4610,
    0xd305, 0x429a, 0xd0e7, 0x4b0b, 0x4a0b, 0x2100, 0xe006, 0x6800,
    0xf843, 0x0b04, 0x3204, 0xe7f1, 0xf843, 0x1b04, 0x4293, 0xd3fb,
    0xe7d9, 0xbf00, 0x0100, 0x2000, 0x0000, 0x2000, 0xed00, 0xe000,
    0x6b74, 0x0000, 0x0100, 0x2000, 0x099c, 0x2000, 0xb508, 0xf000,
    0xf85c, 0xb918, 0xe8bd, 0x4008, 0xf000, 0xb84e, 0xbd08, 0xf7ff,
    0xbfb5, 0xf7ff, 0xbfb3, 0xf7ff, 0xbfb1, 0x0000, 0x4b01, 0x6018,
    0x4770, 0xbf00, 0x03a0, 0x2000, 0x4a12, 0x4913, 0xb5f0, 0x4d13
};

uint32_t cm0_sample_base = 0x20b4;

uint16_t cm0_sample_code[] = {
    /*           */ 0xb510, 0x4c06, 0x7823, 0x2b00, 0xd107, 0x4b05,
    0x2b00, 0xd002, 0x4804, 0xe000, 0xbf00, 0x2301, 0x7023, 0xbd10, 
    0x00a0, 0x2000, 0x0000, 0x0000, 0x4d50, 0x0000, 0x4b04, 0xb510, 
    0x2b00, 0xd003, 0x4903, 0x4804, 0xe000, 0xbf00, 0xbd10, 0x46c0, 
    0x0000, 0x0000, 0x00a4, 0x2000, 0x4d50, 0x0000, 0xb510, 0x2101, 
    0x200d, 0xf000, 0xfa79, 0xbd10, 0xb510, 0x24fa, 0x4b0a, 0x480b, 
    0x6819, 0xf000, 0xfb72, 0x00a4, 0x2101, 0x200d, 0xf000, 0xfab8, 
    0x0020, 0xf000, 0xf8db, 0x2100, 0x200d, 0xf000, 0xfab1, 0x0020, 
    0xf000, 0xf8d4, 0xbd10, 0x46c0, 0x0000, 0x2000, 0x00bc, 0x2000, 
    0xb510, 0x4802, 0xf000, 0xfe01, 0xbd10, 0x46c0, 0x02f8, 0x2000, 
    0xb510, 0x4802, 0xf000, 0xfdf9, 0xbd10, 0x46c0, 0x00bc, 0x2000, 
    0xb5f7, 0x2401, 0x2603, 0x4f15, 0x4915, 0x0038, 0xf000, 0xfb98, 
    0x4914, 0x4815, 0xf000, 0xfb94, 0x4914, 0x4815, 0xf000, 0xfb90, 
    0x4914, 0x4815, 0xf000, 0xfb8c, 0x4914, 0x4815, 0xf000, 0xfb88, 
    0x4d14, 0x4915, 0x0028, 0xf000, 0xfb83, 0x0039, 0x9600, 0x0023, 
    0x9401, 0x2200, 0x4811, 0xf000, 0xfd65, 0x9600, 0x0029, 0x9401, 
    0x231e, 0x221f, 0x480e, 0xf000, 0xfd5d, 0xbdf7, 0x0534, 0x2000, 
    0x0800, 0x4200, 0x0c00, 0x4200, 0x0538, 0x2000, 0x1000, 0x4200, 
    0x053c, 0x2000, 0x1400, 0x4200, 0x0540, 0x2000, 0x1800, 0x4200, 
    0x0544, 0x2000, 0x0548, 0x2000, 0x1c00, 0x4200, 0x02f8, 0x2000, 
    0x00bc, 0x2000, 0xe7fe, 0x0000, 0x4b03, 0xb510, 0x681b, 0x2b00, 
    0xd000, 0x4798, 0xbd10, 0x46c0, 0x054c, 0x2000, 0xb570, 0x490f, 
    0x4c0f, 0x42a1, 0xd104, 0xf000, 0xf889, 0xf000, 0xfe7f, 0xe7fe, 
    0x4d0c, 0x2300, 0x428d, 0xd0f6, 0x18ca, 0x18e8, 0x42a2, 0xd305, 
    0x4b09, 0x4282, 0xd0ef, 0x4909, 0x2200, 0xe004, 0x6800, 0x3304, 
    0x6010, 0xe7f1, 0xc304, 0x428b, 0xd3fc, 0xe7e4, 0x0000, 0x2000, 
    0x00a0, 0x2000, 0x4d54, 0x0000, 0x00a0, 0x2000, 0x0b88, 0x2000, 
    0xb510, 0xf000, 0xf860, 0x2800, 0xd101, 0xf000, 0xf851, 0xbd10, 
    0x4b01, 0x6018, 0x4770, 0x46c0, 0x054c, 0x2000, 0xb5f7, 0x4813, 
    0x2201, 0x4684, 0x4912, 0x4c13, 0x688e, 0x6863, 0x6805, 0x0e9b, 
    0x4013, 0x9201, 0x6888, 0x6862, 0x9f01, 0x0e92, 0x403a, 0x4667, 
    0x683f, 0x4293, 0xd10e, 0x42bd, 0xd10c, 0x4286, 0xd30a, 0x195b, 
    0x25fa, 0x6848, 0x00ad, 0x1b86, 0x4807, 0x436b, 0x4370, 0x0d00, 
    0x18c0, 0xbdfe, 0x003d, 0x0013, 0x0006, 0xe7e3, 0x0550, 0x2000, 
    0xe010, 0xe000, 0xed00, 0xe000, 0x5555, 0x0000, 0xb570, 0x1e04, 
    0xd010, 0xf7ff, 0xffcb, 0x0005, 0xf000, 0xf81c, 0xf7ff, 0xffc6, 
    0x4b05, 0x1b40, 0x4298, 0xd9f7, 0x23fa, 0x3c01, 0x009b, 0x18ed };



char *register_names[] = {"r0", "r1", "r2", "r3",
			  "r4", "r5", "r6", "r7",
			  "r8", "r9", "r10", "r11",
			  "r4", "sp", "lr", "pc"};
			 

void print_ins()
{
    if (curinst.hints.twowords)
	printf(".%04x ",*mainaddr);
    else
	printf("      ");
    printf("  %s%s ", curinst.opcode, curinst.opcodemod);
    if (curinst.rd >= 0)
	printf("%s, ", register_names[curinst.rd]);
    if (curinst.rn >= 0)
	printf("%s, ", register_names[curinst.rn]);
    if (curinst.rm >= 0)
	printf("%s", register_names[curinst.rm]);
    if (curinst.hints.reglist) {
	putchar('{');
	for (int i=0; i<16; i++) {
	    if (curinst.immval & (1<<i)) {
		printf("%s, ", register_names[i]);
	    }
	}
	putchar('}');
    } else {
	if (curinst.hints.immval) {
	    if (curinst.immval < 10) {
		printf(", #%x", curinst.immval);
	    } else {
		printf(", #0x%x", curinst.immval);
	    }
	}
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    for (mainaddr = codesample;
	 mainaddr < codesample+ (sizeof(codesample)/sizeof(codesample[0]));
	 mainaddr++) {
	bzero(&curinst, sizeof(curinst));
	curinst.rn = curinst.rm = curinst.rd = -1;  // reset
	printf("0x%06x: ", sample_base +  (uint32_t) (mainaddr-codesample)*2);
	printf("%04x", *mainaddr);
	if (scan_table(mainaddr, *mainaddr>>8, table_top) >= 0) {
	    print_ins();
	} else {
	    printf("    0x%04x // not understood\n", *mainaddr);
	}
    }
}
