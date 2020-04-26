#ifndef H_TAINTCHECK_HOOK_H
    #define H_TAINTCHECK_HOOK_H
    
    /* For module function summary calculation, at the end of each hooked function, all symbolic-state 
       modifications of the function body would be summarized as a post-condition, while function's local
       path-expression would be ascribed to a pre-condition !

       This module is designed for post-condition calculation. although need not care about registers'  
       and EFLAGS' taint states, we should focus on the memory cases.
     */

    #include <inttypes.h>
    #include "H_taint_record.h"


    // 1 byte per unit
    typedef struct h_func_taint_mem_record_entry
    {
	uint32_t	 vaddr;	
	H_taint_record_t record;
	struct h_func_taint_mem_record_entry * next;
    }h_func_taint_mem_record_entry_t, *Ph_func_taint_mem_record_entry_t;


    typedef struct h_func_taint_mem_record_list
    {
	h_func_taint_mem_record_entry_t * head;
	h_func_taint_mem_record_entry_t * end;
	int count;

	struct h_func_taint_mem_record_list *  next;
    }h_func_taint_mem_record_list_t, *Ph_func_taint_mem_record_list_t;


/*
    typedef struct h_func_taint_mem_record_list_list
    {
	h_func_taint_mem_record_list_t * head;
	h_func_taint_mem_record_list_t * end;
	int count;	
    }h_func_taint_mem_record_list_list_t, *Ph_func_taint_mem_record_list_list_t;
 */
    /*
    typedef struct h_func_taint_reg_record_entry
    {
	uint32_t regidx;
	uint32_t regoffset,
	uint32_t regsize;

	struct h_func_taint_reg_record_entry * next;
    }h_func_taint_reg_record_entry_t, *Ph_func_taint_reg_record_entry_t;


    typedef struct h_func_taint_reg_record_list
    {
	h_func_taint_reg_record_entry_t head;
	h_func_taint_reg_record_entry_t end;
	int count;
    }h_func_taint_reg_record_list_t, *Ph_func_taint_reg_record_list_t;
    */

    void func_taint_memory_record_list_init(h_func_taint_mem_record_list_t * mem_data);
    // void func_taint_memory_record_list_init( );
    
    void func_taint_memory_record_list_restore(h_func_taint_mem_record_list_t * mem_data);


    // callback invoked when mem[vaddr] is tainted
    void H_func_add_taint_memory_record_entry( uint32_t 	  vaddr,
					       H_taint_record_t * record					       
					     );

    // callback invoked when mem[vaddr]'s taint status is cleared
    void H_func_delete_taint_memory_record_entry(uint32_t vaddr);

    void func_taint_memory_record_list_delete(h_func_taint_mem_record_list_t * mem_data);

    void taintcheck_virtmem_hookfn( uint32_t 	       vaddr,
				    uint32_t	       size,
				    uint32_t	       tcbmap,
				    H_taint_record_t * records
		    	          );

    void Copy_taint_mem_list( h_func_taint_mem_record_list_t * src_list,
		  	      h_func_taint_mem_record_list_t * dst_list
		            );

#endif




