/*  mov [AA], b
    b is a constant, AA is symbolic address, aa is AA's runtime concrete value
    As TEMU would clean out the taint-status of aa, I would save aa at plg'time, then restore it when analysis as 
    the IR-SYMEXE would save to all AA's possible concrete addresses a constructed symbolic value !
 */
#ifndef H_TC_SYMADDR_MEM_RESTORE_H
    #include <inttypes.h>
    #include "H_taint_record.h"

    typedef struct tc_symaddr_mem_addr_entry
    {
	uint32_t vaddr;
	uint32_t size;
	uint64_t tc_bmap;
        
	H_taint_record_t * records;
	struct tc_symaddr_mem_addr_entry * next;
    }tc_symaddr_mem_addr_entry_t, *Ptc_symaddr_mem_addr_entry_t;

    typedef struct tc_symaddr_mem_addr_list
    {
	struct tc_symaddr_mem_addr_entry * head;
	struct tc_symaddr_mem_addr_entry * tail;

	int  count;
    }tc_symaddr_mem_addr_list_t, *Ptc_symaddr_mem_addr_list;


    /* ---------------------------------------------------------------------------- */
    void init_tc_symaddr_mem_restore_list( );

    void add_tc_symaddr_mem_addr_entry_to_list( uint32_t	       vaddr,
					        uint32_t 	       size,
					        uint64_t 	       taint_bmap,
					        H_taint_record_t * records
					  );

    void delete_restore_tc_symaddr_mem_list( );    
    /* ---------------------------------------------------------------------------- */

#endif
