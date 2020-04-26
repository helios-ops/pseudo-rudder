#ifndef H_LOOP_ANALYSIS_H

    #define H_LOOP_ANALYSIS_H

    #include <inttypes.h>

    // basic-block's representation 
    typedef struct bb_entry
    {
	uint32_t start_addr;
	uint32_t end_addr;

	struct bb_entry * next;
	void *		  loop; 
    }bb_entry_t, *Pbb_entry_t;

    // loop-structure's representation
    typedef struct loop_entry
    {
	bb_entry_t * bb_head;
	bb_entry_t * bb_head;
	int	     bb_count;
	int	     loop_level;  // nested level

	struct loop_entry * next; // loop-chain
    }loop_entry_t, *Ploop_entry_t;


    typedef struct loop_entry_list
    {
	loop_entry_t * head;
	loop_entry_t * end;
	int count;
    }loop_entry_list_t, *Ploop_entry_list_t;


    void init_loop_analysis( );

    int Check_LoopHdr_by_va( uint32_t 	vaddr,
		             loop_entry_t * lentry
		           );

#endif
