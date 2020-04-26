#ifndef H_CALL_ANALYSIS_H
    #define H_CALL_ANALYSIS_H

    #include <inttypes.h>

    typedef struct H_callstack_entry
    {
	uint32_t ebp;
	struct H_callstack_entry * prev;	
	struct H_callstack_entry * next;
    }H_callstack_entry_t, *PH_callstack_entry_t;

    typedef struct H_callstack_list
    {
	struct H_callstack_entry * head;
	struct H_callstack_entry * end;
	int    count;
    }H_callstack_list_t, *PH_callstack_list_t;


    void H_callstack_snapshot_util_init( );

    void H_callstack_list_init( );

    void H_callstack_list_delete( );

    void H_callstack_list_add_entry(uint32_t ebp);

    void H_call_analysis(uint32_t next_eip);

    int Find_callstack_by_vaddr( uint32_t   vaddr,
			         uint32_t * eip_base
			       );

    int Fetch_all_ebps_from_callstack(uint32_t ** ebp_array);

    void dump_callstack( );

#endif
