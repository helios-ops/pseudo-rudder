/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/// @file TEMU_main.h
/// @author: Heng Yin <hyin@ece.cmu.edu>
/// \addtogroup main temu: Main TEMU Module


#ifndef _TEMU_MAIN_H_INCLUDED_
#define _TEMU_MAIN_H_INCLUDED_


#undef INLINE

#include "config.h"

#ifdef TARGET_X86_64
#define TARGET_LONG_BITS 64
#else
#define TARGET_LONG_BITS 32
#endif

#include "cpu-defs.h"

#include "fpu/softfloat.h"

#include "./sample_plugin/H_test_config.h"


#if TAINT_ENABLED
#include "taintcheck.h"
#endif

#include "./sample_plugin/hc_interface.h"

#include "./sample_plugin/FileHandle.h"


#include "./sample_plugin/thread_context.h"

// should we use protocol analysis results ??
#ifdef H_USE_PROTOCOL_ANALYSIS
#include "./sample_plugin/combine_protocol_analysis.h"
#endif


#ifdef H_DEBUG_TEST
#include "../sample_plugin/dbg_util.h"
#endif

/*** Define Registers ***/
/* copied from shared/disasm.h */

/* segment registers */
#define es_reg 100
#define cs_reg 101
#define ss_reg 102
#define ds_reg 103
#define fs_reg 104
#define gs_reg 105

/* address-modifier dependent registers */
#define eAX_reg 108
#define eCX_reg 109
#define eDX_reg 110
#define eBX_reg 111
#define eSP_reg 112
#define eBP_reg 113
#define eSI_reg 114
#define eDI_reg 115

/* 8-bit registers */
#define al_reg 116
#define cl_reg 117
#define dl_reg 118
#define bl_reg 119
#define ah_reg 120
#define ch_reg 121
#define dh_reg 122
#define bh_reg 123

/* 16-bit registers */
#define ax_reg 124
#define cx_reg 125
#define dx_reg 126
#define bx_reg 127
#define sp_reg 128
#define bp_reg 129
#define si_reg 130
#define di_reg 131

/* 32-bit registers */
#define eax_reg 132
#define ecx_reg 133
#define edx_reg 134
#define ebx_reg 135
#define esp_reg 136
#define ebp_reg 137
#define esi_reg 138
#define edi_reg 139

#define eip_reg 140
#define cr3_reg 141




#ifndef CPU_I386_H

#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7
#if 1//TAINT_ENABLED
#define R_T0 CPU_NB_REGS
#define R_T1 (CPU_NB_REGS + 1)
#define R_A0 (CPU_NB_REGS + 2)
#define R_CC_SRC (CPU_NB_REGS + 3)
#define R_CC_DST (CPU_NB_REGS + 4)
#endif

#define R_ES 0
#define R_CS 1
#define R_SS 2
#define R_DS 3
#define R_FS 4
#define R_GS 5

#define HF_CPL_SHIFT         0
#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)

#define CR0_PE_MASK  (1 << 0)
#define CR0_MP_MASK  (1 << 1)
#define CR0_EM_MASK  (1 << 2)
#define CR0_TS_MASK  (1 << 3)
#define CR0_ET_MASK  (1 << 4)
#define CR0_NE_MASK  (1 << 5)
#define CR0_WP_MASK  (1 << 16)
#define CR0_AM_MASK  (1 << 18)
#define CR0_PG_MASK  (1 << 31)

#define CR4_VME_MASK  (1 << 0)
#define CR4_PVI_MASK  (1 << 1)
#define CR4_TSD_MASK  (1 << 2)
#define CR4_DE_MASK   (1 << 3)
#define CR4_PSE_MASK  (1 << 4)
#define CR4_PAE_MASK  (1 << 5)
#define CR4_PGE_MASK  (1 << 7)
#define CR4_PCE_MASK  (1 << 8)
#define CR4_OSFXSR_MASK (1 << 9)
#define CR4_OSXMMEXCPT_MASK  (1 << 10)


#define PG_PRESENT_BIT	0
#define PG_RW_BIT	1
#define PG_USER_BIT	2
#define PG_PWT_BIT	3
#define PG_PCD_BIT	4
#define PG_ACCESSED_BIT	5
#define PG_DIRTY_BIT	6
#define PG_PSE_BIT	7
#define PG_GLOBAL_BIT	8
#define PG_NX_BIT	63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK	 (1 << PG_RW_BIT)
#define PG_USER_MASK	 (1 << PG_USER_BIT)
#define PG_PWT_MASK	 (1 << PG_PWT_BIT)
#define PG_PCD_MASK	 (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK	 (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK	 (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK	 (1 << PG_GLOBAL_BIT)
#define PG_NX_MASK	 (1LL << PG_NX_BIT)

#ifdef TARGET_X86_64
#define CPU_NB_REGS 16
#else
#define CPU_NB_REGS 8
#endif


typedef struct SegmentCache {
    uint32_t selector;
    uint32_t base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
    float32 _s[4];
    float64 _d[2];
} XMMReg;

typedef union {
    uint8_t _b[8];
    uint16_t _w[2];
    uint32_t _l[1];
    uint64_t q;
} MMXReg;

#ifdef FLOATX80
#define USE_X86LDOUBLE
#endif

#ifdef USE_X86LDOUBLE
typedef floatx80 CPU86_LDouble;
#else
typedef float64 CPU86_LDouble;
#endif


#endif

typedef union {
#ifdef USE_X86LDOUBLE
        CPU86_LDouble d __attribute__((aligned(16)));
#else
#error host architecture other than IA-32 and IA-64 is not supported
        CPU86_LDouble d;
#endif
        MMXReg mmx;
} FPReg;


/* @{ */ //start of group

//move from monitor.c
/// structure for defining a terminal command
typedef struct term_cmd_t {
    const char *name; /// command name
    const char *args_type; /// command argument list
    void (*handler)(); /// command handler
    const char *params; /// parameters of command handler
    const char *help; /// help message
} term_cmd_t;

/* Static in monitor.c for QEMU, but we use it for plugins: */
///send a keystroke into the guest system
void do_send_key(const char *string);

/// \brief read or write a physical memory region
///
/// @param addr physical address
/// @param buf buffer (output buffer for read and input buffer for write)
/// @param len length of memory region
/// @param is_write true for write and false for read
void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);

/// print a message to TEMU terminal
extern void term_printf(const char *fmt, ...);


/*
 * These are extracted from CPUX86State
 */
/// array of CPU general-purpose registers, such as R_EAX, R_EBX
extern target_ulong *TEMU_cpu_regs; 
/// pointer to instruction pointer EIP
extern target_ulong *TEMU_cpu_eip;
/// pointer to EFLAGS
extern target_ulong *TEMU_cpu_eflags;
/// pointer to hidden flags
extern uint32_t *TEMU_cpu_hflags;
/// array of CPU segment registers, such as R_FS, R_CS
extern SegmentCache *TEMU_cpu_segs;
/// pointer to LDT
extern SegmentCache *TEMU_cpu_ldt;
/// pointer to GDT
extern SegmentCache *TEMU_cpu_gdt;
/// pointer to IDT
extern SegmentCache *TEMU_cpu_idt;
/// array of CPU control registers, such as CR0 and CR1
extern target_ulong *TEMU_cpu_cr;
/// pointer to DF register
extern int32_t *TEMU_cpu_df; 
/// array of XMM registers
extern XMMReg *TEMU_cpu_xmm_regs;
/// array of MMX registers
extern MMXReg *TEMU_cpu_mmx_regs;
/// FPU - array of Floating Point registers
extern FPReg *TEMU_cpu_fp_regs;
/// FPU - top of Floating Point register stack 
extern unsigned int * TEMU_cpu_fp_stt;
/// FPU - Status Register
extern unsigned int * TEMU_cpu_fpus;
/// FPU - Control Register
extern unsigned int * TEMU_cpu_fpuc;
/// FPU - Tag Register
extern uint8_t * TEMU_cpu_fptags;


extern uint32_t *TEMU_cc_op;

/// primary structure for TEMU plugin, including callbacks and states
typedef struct {
  /// array of terminal commands
  term_cmd_t *term_cmds; 
  /// array of informational commands
  term_cmd_t *info_cmds; 
  /*!
   * \brief callback for cleaning up states in plugin.
   * TEMU plugin must release all allocated resources in this function
   */


  // char * x86_cpu;

/* ===================================================================== */
  void (*hvm_load)( );
/* ===================================================================== */

  uint32_t * symexe_handle;



  void (*plugin_cleanup)(); 
#if TAINT_ENABLED
  /// \brief size of taint record for each tainted byte. 
  /// TEMU sees taint record as untyped buffer, so it only cares about the 
  /// size of taint record
  int taint_record_size; 

#define PROP_MODE_MOVE 	0
#define PROP_MODE_XFORM	1

  /* HHui Added at April 14th, 2011
     IR SymExe needs the symbolic-machine state before the concrete instruction's execution.
     Therefore, when taint propagates, we let TEMU call before_taint_propagate( ) to allow us
     remain the symbolic machine state before concrete execution when analyzing the specific 
     instruction's IR form.
   */
  /* This function would be called by TEMU. 
     Return value 1 tells TEMU NOT to carry out the taint propagation to keep the symbolic state.     
   */
  int (* before_taint_propagate)();


  // Restore the concrete value of those originally clean dst operands but tainted by instruction for SYMBOLIC EXECUTION 
  void (* get_insn_dst_concrete_value)( taint_operand_t *dst_oprnd );


  /// \brief This callback customizes its own policy for taint propagation
  ///
  /// TEMU asks plugin how to propagate tainted data. If the plugin does not 
  /// want to customize the propagation policy, it can simply specify 
  /// default_taint_propagate().
  ///
  /// @param nr_src number of source operands
  /// @param src_oprnds array of source operands
  /// @param dst_oprnd destination operand
  /// @param mode mode of propagation (either direct move or transformation)  

  void (*taint_propagate) (int nr_src, taint_operand_t *src_oprnds, 
		taint_operand_t *dst_oprnd, int mode);
#endif 

  /// \brief This callback handles OS-level semantics information.
  ///
  /// It needs to parse the message and maintain process, module, and function 
  /// information, using functionality in \ref semantics.
  void (*guest_message) (char *message);

  void (*send_keystroke) (int reg);
#ifdef DEFINE_BLOCK_BEGIN
  /// This callback is invoked at the beginning of each basic block
  int (*block_begin) ();
#endif  
#ifdef DEFINE_BLOCK_END
  /// This callback is invoked at the end of each basic block
  void (*block_end) ();
#endif
#ifdef DEFINE_INSN_BEGIN
  /// This callback is invoked at the beginning of each instruction
  void (*insn_begin) ();
#endif
#ifdef DEFINE_INSN_END
  /// This callback is invoked at the end of each instruction
  void (*insn_end) ();
#endif
  void (*bdrv_open) (int index, void *opaque);
  void (*taint_disk) (uint64_t addr, uint8_t * record, void *opaque);
  void (*read_disk_taint)(uint64_t addr, uint8_t * record, void *opaque);
  /// This callback is invoked when a network packet is received by NIC
  void (*nic_recv) (uint8_t * buf, int size, int cur_pos, int start,
                    int stop);
  /// This callback is invoked when a network packet is sent out by NIC
  void (*nic_send) (uint32_t addr, int size, uint8_t * buf);


/* ============== HHui added callback for JCC monitoring ============== */
  void (*HHui_conjmp)(uint32_t opdata);
/* ===================================================================== */

  int (*cjmp) (uint32_t t0);


#ifdef DEFINE_EIP_TAINTED
  void (*eip_tainted) (uint8_t * record);
#endif
#ifdef DEFINE_MEMREG_EIP_CHANGE
  void (*memreg_eip_change)();
#endif
  void (*after_loadvm) (const char *param);
#ifdef CHEAT_SIDT
  int (*cheat_sidt) ();
#endif
  /// \brief CR3 of a specified process to be monitored.
  /// 0 means system-wide monitoring, including all processes and kernel.
  uint32_t monitored_cr3;

#ifdef MEM_CHECK
  /// \brief This callback is invoked when the current instruction reads a memory region.
  ///
  /// @param virt_addr virtual address of memory region
  /// @param phys_addr physical address of memory region
  /// @param size size of memory region
  void (*mem_read)(uint32_t virt_addr, uint32_t phys_addr, int size);
  /// \brief This callback is invoked when the current instruction writes a memory region.
  ///
  /// @param virt_addr virtual address of memory region
  /// @param phys_addr physical address of memory region
  /// @param size size of memory region
  void (*mem_write)(uint32_t virt_addr, uint32_t phys_addr, int size);
#endif

#ifdef REG_CHECK
  /// \brief This callback is invoked when the current instruction reads a register.
  ///
  /// @param regidx register index, e.g., the index of R_BH is R_EBX*4 + 1
  /// @param size size of register in bytes
  void (*reg_read)(uint32_t regidx, int size);

  /// \brief This callback is invoked when the current instruction writes a register.
  ///
  /// @param regidx register index, e.g., the index of R_BH is R_EBX*4 + 1
  /// @param size size of register in bytes
  void (*reg_write)(uint32_t regidx, int size);
#endif


/* ============== HHui added callback for obtaining the concrete values before monitored targets' modification ============== */
/*
void (* HHui_memory_access)( uint32_t addr,
			     int      size,
			     int      access_mode // 0 -- read ; 1 -- write
			   );
*/

void (* HHui_write_memory_access)( uint32_t addr,
			     	   int      size
			   	 );



void (* HHui_write_register_access)( uint32_t regidx,
				     int      offset,
			      	     int      size
			   	   );


/* get the modified EFLAGS during an instruction's execution, which would be used to 
   make the neccessary taint-cleanup when the instruction is concrete, so as to guide 
   correct SYM-EXE when JCC is encounted asking for tainted predicates
 */
void (* HHui_modify_EFLAGS_access)( uint32_t bits_accessed
				  );


void (* HHui_symbolic_addressing_check)(uint32_t reg_idx);
/* ==========================================================================================================================  */




#ifdef HANDLE_INTERRUPT
  /// \brief This callback indicates an interrupt is happening
  ///
  /// @param intno interrupt number
  /// @param is_int is it software interrupt?
  /// @param next_eip EIP value when interrupt returns
  void (*do_interrupt)(int intno, int is_int, uint32_t next_eip);

  /// This callback indicates an interrupt is returned
  void (*after_iret_protected)();
#endif

#ifdef CALLSTRING_ANALYSIS
  void (*call_analysis)(uint32_t next_eip);
#endif

#ifdef PRE_MEM_WRITE
  void (*pre_mem_write)(uint32_t virt_addr, uint32_t phys_addr, int size);
#endif


  // HHui added callback for tainted branchings' states saving and loading
  /* ==========================================================================================================================  */
  /*
  void(*branch_vm_store)( );
  void(*branch_vm_load)( );
   */
  /* ==========================================================================================================================  */



  /* HHui added at May 25th, 2011 for branch_update_VM's register updates ! */
  char * x86_cpu;


  // HHui added at May 25th, 2011 for automatic derivation of multiple paths' constraints !
  /* ----------------------------------------------------------------------------------- */
  void (*BFS_restore_HVM_state_from_snapshot)( );

  int monproc_terminated;   
  /* ----------------------------------------------------------------------------------- */ 
  // for automatic derivation of multiple paths' constraints !


  uint32_t monitored_pid;
  uint32_t p_eprocess;
  int	   p_eprocess_got;

  void *   monitored_vad;
  void * (* obtain_vad)( void * eproc );

  /* returns 1 if true; otherwise 0 */
  int (*IsInMonitoredModules)(uint32_t current_eip);


  // File-related API-Hooking  
  /* ---------------------------------------------------------------------------------- */ 
  // util for Readfile( )
  Pfile_handle_entry_t  (*fetch_filehandle_entry_by_fd)(int fd);

  PfileMapping_handle_entry_list_t (*fetch_fileMappinghandle_entry_by_handle)(int fd);

  // util for OpenFile( )
  void (*add_filehandle_to_list)( char * name, 
			          // int    namelen,
			          int    fd
			        );
  void (*add_fileMappinghandle_to_list)( uint32_t	       fmap_name,
					 int 	  	       fmap_d,
				         file_handle_entry_t * file_entry,
					 int    	       size,
					 int		       a_or_w
				       );

  // util for CloseFile( )
  void (*delete_filehandle_from_list)(int fd);


#ifdef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
  char ** interested_file_names;
  int     interested_file_count; 
#endif


/* here are several state-monitoring utils which we could change by calling the corresponding 
   modifying functions during the debugging session. 
   Notify: when we build the final version, these should be disabled !
 */
#ifdef HHUI_DEBUG_MODIFY_STATE
  int     dbg_enable_taint;
#endif

  /* ---------------------------------------------------------------------------------- */ 
  // File-related API-Hooking 


  // Heap-related hooking utils
  /* ---------------------------------------------------------------------------------- */
  void (*add_entry_to_heap_data_list)( uint32_t addr,
			   	       uint32_t size
			  	     );
  void (*delete_entry_from_heap_data_list)(uint32_t addr);
  /* ---------------------------------------------------------------------------------- */ 
  // Heap-related hooking utils

   
  /* compositional symbolic execution related : 
     we introduce taints only in a hooked function's context in the focused module's domain 
   */
  /* ---------------------------------------------------------------------------------- */
  int is_in_focused_module;

  int focused_func_started;

  void * cur_func_summ_entry;

  // set when post-condition is judged to be applied so as to ignore sym-exe.
  int func_postcondition_enable;

  int pre_post_cond_snapshot;

  void (*h_taintcheck_virtmem_hookfn)( uint32_t  vaddr,
				       uint32_t	 size,
				       uint32_t	 tcbmap,
				       uint8_t * records
			    	     );
  
  /* ---------------------------------------------------------------------------------- */


  void (*HHui_encap_taintcheck_taint_virtmem)( uint32_t  vaddr,
					       uint32_t  size,
					       uint64_t  taint,
					       uint8_t * records
					     );

  void (*HHui_record_error_expr_2_file)(char * str_info);

#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  uint32_t current_monitored_thread;
#endif


#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK
  uint32_t is_in_cur_interested_func;
#endif


#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
  uint32_t symexe_enabled_for_taint;
#endif


#ifdef H_DEBUG_TEST
  uint32_t dbg_interested_eip;
#endif

#ifdef HH_TRACE_MONITOR
  int trace_fd;  
#endif

  HVC hvc;


// should we make hardcodingly patch in order to save-load correct thread-context ??
#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
  temu_thread_context_util_t * thc_util;
#endif

#ifdef H_USE_PROTOCOL_ANALYSIS
  protocol_analysis_util_t * proto_util;  
#endif


// HHui added at March 15th, 2012
#ifdef H_DEBUG_TEST
  h_dbg_util_t * temu_dbg_util;
#endif

} plugin_interface_t;

/// This flag tells if emulation mode is enabled
extern int TEMU_emulation_started;

/****** Functions used by TEMU plugins ****/


void TEMU_EFLAGS_write( int bit_index,
			int bit_value
		      );

/// \brief Read from a register.
///
/// Note that reg_id is register ID, which is different from register index.
/// Register ID is defined by Kruegel's disassembler, whereas register index is 
/// the index of CPU register array.
/// @param reg_id register ID
/// @param buf output buffer of the value to be read
void TEMU_read_register(int reg_id, void *buf);

/// \brief Write into a register.
///
/// Note that reg_id is register ID, which is different from register index.
/// Register ID is defined by Kruegel's disassembler, whereas register index is 
/// the index of CPU register array.
/// @param reg_id register ID
/// @param buf input buffer of the value to be written
void TEMU_write_register(int reg_id, void *buf);

/// Convert virtual address into physical address
target_ulong TEMU_get_phys_addr(target_ulong addr);

/// \brief Given a virtual address, this function returns the page access status.
///
///  @param addr virtual memory address
///  @return page access status: -1 means not present, 0 means readonly, 
///   and 1 means writable.
int TEMU_get_page_access(uint32_t addr);

int TEMU_memory_rw(uint32_t addr, void *buf, int len, int is_write);

/// \brief Read from a memory region by its virtual address.
///
/// @param vaddr virtual memory address
/// @param len length of memory region (in bytes)
/// @param buf output buffer of the value to be read
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted 
/// into physical address. It could be either invalid address or swapped out.
int TEMU_read_mem(uint32_t vaddr, int len, void *buf);

/// \brief Write into a memory region by its virtual address.
///
/// @param vaddr virtual memory address
/// @param len length of memory region (in bytes)
/// @param buf input buffer of the value to be written
/// @return status: 0 for success and -1 for failure
///
/// If failure, it usually means that the given virtual address cannot be converted 
/// into physical address. It could be either invalid address or swapped out.
int TEMU_write_mem(uint32_t vaddr, int len, void *buf);


int TEMU_read_mem_with_cr3(target_ulong cr3, uint32_t vaddr, int len, void *buf);
int TEMU_write_mem_with_cr3(target_ulong cr3, uint32_t vaddr, int len, void *buf); 

/// Pause the guest system
void TEMU_stop_vm();

/// Check if the current execution of guest system is in kernel mode (i.e., ring-0)
static inline int TEMU_is_in_kernel()
{
  return ((*TEMU_cpu_hflags & HF_CPL_MASK) == 0);
}


/* @} */ //end of group


extern plugin_interface_t *temu_plugin;
extern void * TEMU_KbdState;
extern int should_monitor; //!<this flag indicates whether the plugin should receive callback

int TEMU_bdrv_pread(void *bs, int64_t offset, void *buf, int count); //for SleuthKit

/****** Functions used internally ******/
void do_enable_emulation(void);
void do_disable_emulation(void);
void do_load_plugin(const char *plugin_path);
void do_unload_plugin(void);
void TEMU_nic_receive(const uint8_t * buf, int size, int cur_pos, int start, int stop);
void TEMU_nic_send(uint32_t addr, int size, uint8_t * buf);
void TEMU_nic_in(uint32_t addr, int size);
void TEMU_nic_out(uint32_t addr, int size);
void TEMU_read_keystroke(void *s);
void TEMU_virtdev_init();
void TEMU_after_loadvm();
void TEMU_init();
#ifdef DEFINE_BLOCK_BEGIN
int TEMU_block_begin();
#endif
#ifdef DEFINE_INSN_BEGIN
void TEMU_insn_begin(uint32_t pc_start);
#endif
#ifdef DEFINE_INSN_END
void TEMU_insn_end();
#endif
void TEMU_update_cr3();
void TEMU_do_interrupt(int intno, int is_int, target_ulong next_eip);
void TEMU_after_iret_protected(void);
void TEMU_update_cpustate();
void TEMU_loadvm(void *opaque);


#include "TEMU_vm_compress.h"

#endif //_TEMU_MAIN_H_INCLUDED_
