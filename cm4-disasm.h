/*
 * cm4-disasm.h
 * Copyright 2020 by Bill Westfield (westfw@yahoo.com)
 */

typedef struct decoded_ {
    int32_t immval;
    char opcode[10];
    char opcodemod[10];
    int8_t rn;
    int8_t rm;
    int8_t rd;
    struct {
	uint8_t has_immval:1;
	uint8_t brackets:1;
	uint8_t reglist:1;
	uint8_t twowords:1;
	uint8_t immval:1;
    } hints;
} decoded_t;

typedef void (*decode_func_t)(uint16_t *addr, uint32_t ins);

typedef struct decode8_entry_ {
    uint8_t mask;
    uint8_t val;
    decode_func_t func;
    uint8_t hint;
} decode_entry_t;

/*
 */
int scan_table(uint16_t *addr, uint32_t ins, const decode_entry_t *table);


void subdecode_im5lmld(uint16_t *addr, uint32_t ins);
void subdecode_rsrmrd(uint16_t *addr, uint32_t ins);
void subdecode_im3(uint16_t *addr, uint32_t ins);
void subdecode_im8(uint16_t *addr, uint32_t ins);

void decode_lsl(uint16_t *addr, uint32_t ins);
void decode_lsr(uint16_t *addr, uint32_t ins);
void decode_asr(uint16_t *addr, uint32_t ins);
void decode_addsubr(uint16_t *addr, uint32_t ins);
void decode_mov(uint16_t *addr, uint32_t ins);
void decode_cmp(uint16_t *addr, uint32_t ins);
void decode_addim8(uint16_t *addr, uint32_t ins);
void decode_subim8(uint16_t *addr, uint32_t ins);
void decode_logic(uint16_t *addr, uint32_t ins);
void decode_dp(uint16_t *addr, uint32_t ins);
void decode_specdp(uint16_t *addr, uint32_t ins);
void decode_thumb32(uint16_t *addr, uint32_t ins);
void decode_error(uint16_t *addr, uint32_t ins);
void decode_ldvpc(uint16_t *addr, uint32_t ins);
void decode_ldst(uint16_t *addr, uint32_t ins);
void decode_adr(uint16_t *addr, uint32_t ins);
void decode_addsp4(uint16_t *addr, uint32_t ins);
void decode_multiple(uint16_t *addr, uint32_t ins);
void decode_bcc(uint16_t *addr, uint32_t ins);
void decode_branchc(uint16_t *addr, uint32_t ins);
void decode_branch(uint16_t *addr, uint32_t ins);
void decode_blx(uint16_t *addr, uint32_t ins);
void decode_bprefix(uint16_t *addr, uint32_t ins);
void decode_bl(uint16_t *addr, uint32_t ins);

void decode_add_r(uint16_t *addr, uint32_t ins);
void decode_subr(uint16_t *addr, uint32_t ins);
void decode_addim3(uint16_t *addr, uint32_t ins);
void decode_subim3(uint16_t *addr, uint32_t ins);

void  decode_addsubsp(uint16_t  *addr, uint32_t ins);
void  decode_extend(uint16_t  *addr, uint32_t ins);
void  decode_push(uint16_t  *addr, uint32_t ins);
void  decode_pop(uint16_t  *addr, uint32_t ins);

void decode_ldst5(uint16_t *addr, uint32_t ins);
void decode_ldst678(uint16_t *addr, uint32_t ins);
void decode_ldst9(uint16_t *addr, uint32_t ins);
void decode_cpumisc(uint16_t *addr, uint32_t ins);


void decode_cps(uint16_t *addr, uint32_t ins);
void decode_cbz(uint16_t *addr, uint32_t ins);
void decode_sxth(uint16_t *addr, uint32_t ins);
void decode_sxtb(uint16_t *addr, uint32_t ins);
void decode_uxth(uint16_t *addr, uint32_t ins);
void decode_uxtb(uint16_t *addr, uint32_t ins);
void decode_cbnz(uint16_t *addr, uint32_t ins);
void decode_rev(uint16_t *addr, uint32_t ins);
void decode_rev16(uint16_t *addr, uint32_t ins);
void decode_revsh(uint16_t *addr, uint32_t ins);
void decode_cbnz(uint16_t *addr, uint32_t ins);
void decode_bkpt(uint16_t *addr, uint32_t ins);
void decode_it(uint16_t *addr, uint32_t ins);
void decode_subsp7(uint16_t *addr, uint32_t ins);

void decode_branch32misc(uint16_t *addr, uint32_t ins);
void decode_b32misc (uint16_t *addr, uint32_t ins);
void decode_undefined32(uint16_t *addr, uint32_t ins);
void decode_branch32(uint16_t *addr, uint32_t ins);
void decode_bl32(uint16_t *addr, uint32_t ins);
void decode_more32(uint16_t *addr, uint32_t ins);


void decode_32ldstm(uint16_t *addr, uint32_t ins);
void decode_32ldstx(uint16_t *addr, uint32_t ins);
void decode_32dpshreg(uint16_t *addr, uint32_t ins);
void decode_32coproc(uint16_t *addr, uint32_t ins);

void decode_32dpmod(uint16_t *addr, uint32_t ins);
void decode_32dpplain(uint16_t *addr, uint32_t ins);

void decode_32st(uint16_t *addr, uint32_t ins);
void decode_32ldb(uint16_t *addr, uint32_t ins);
void decode_32ldh(uint16_t *addr, uint32_t ins);
void decode_32ld(uint16_t *addr, uint32_t ins);
void decode_undefined(uint16_t *addr, uint32_t ins);

void decode_32dpreg(uint16_t *addr, uint32_t ins);
void decode_32multiply(uint16_t *addr, uint32_t ins);
void decode_32lmultiply(uint16_t *addr, uint32_t ins);
void decode_32coproc(uint16_t *addr, uint32_t ins);
void decode_movregall(uint16_t *addr, uint32_t ins);
void decode_cmpregall(uint16_t *addr, uint32_t ins);
void decode_addregall(uint16_t *addr, uint32_t ins);
void decode_bx(uint16_t *addr, uint32_t ins);
void decode_blx(uint16_t *addr, uint32_t ins);


uint32_t cm0_sample_base;
uint16_t cm0_sample_code[];
uint32_t cm4_sample_base;
uint16_t cm4_sample_code[];
