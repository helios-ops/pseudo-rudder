#ifndef H_PSEUDO_X86_CPU_H

    #define H_PSEUDO_X86_CPU_H
    typedef struct pseudo_x86_cpu
    {
	uint32_t regs[8*2];
	uint32_t tempidx;
	uint32_t eip;
	uint32_t eflags;

    }pseudo_x86_cpu_t, *Ppseudo_x86_cpu_t;

#endif
