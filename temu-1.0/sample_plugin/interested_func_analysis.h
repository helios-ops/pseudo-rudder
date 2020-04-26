#ifndef H_INTERESTED_FUNC_ANALYSIS_H
    #define H_INTERESTED_FUNC_ANALYSIS_H

    #include <inttypes.h>

    typedef struct h_interested_func_entry
    {
	uint32_t addr;
	char	 name[30];
	
	struct h_interested_func_entry * next;
    }h_interested_func_entry_t, *Ph_interested_func_entry_t;

    typedef struct h_interested_func_list
    {
	struct h_interested_func_entry * head;
	struct h_interested_func_entry * end;

	int count;
    }h_interested_func_list_t, *Ph_interested_func_list_t;

    
    void interest_func_list_init( );
    void interest_func_list_delete( );

    int is_interested_func(char * str_func_name);
    void hook_interested_func( int 	HHui_tmp_findex,
			       uint32_t HHui_tmp_vaddr,
			       uint32_t HHui_tmp_argsize
			     );

#endif
