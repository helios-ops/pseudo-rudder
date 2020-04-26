#ifndef H_FUNC_SUMM_HOOK_H
    #define H_FUNC_SUMM_HOOK_H

    #include <inttypes.h>
    #include "../shared/hookapi.h"

    typedef struct fun_ret_hook_entry
    {
	uint32_t     eip;
	uint32_t     esp;
	hook_proc_t  hookfn;
	void *	     func_entry;
	uint32_t     sizeof_opaque;
	
	struct fun_ret_hook_entry * prev;
	struct fun_ret_hook_entry * next;
    }fun_ret_hook_entry_t, *Pfun_ret_hook_entry_t;


    typedef struct func_ret_hook_list
    {
	fun_ret_hook_entry_t * head;
	fun_ret_hook_entry_t * end;
	int		       count;
    }func_ret_hook_list_t, *Pfunc_ret_hook_list_t;
    /*
    void func_hook_save( QEMUFile * f,
			 void     * opaque
		       );

    int func_hook_load( QEMUFile * f,
		        void     * opaque,
  		        int	   version_id
		      );
    */

    void init_func_ret_hook_list( );
    void delete_func_ret_hook_list( );

    void del_tail_entry_from_func_ret_hook_list( uint32_t    eip,
					         uint32_t    esp,
					         hook_proc_t hookfn
				               );

    void add_entry_2_func_ret_hook_list( uint32_t    eip,
					 uint32_t    esp,
				         hook_proc_t hookfn,
				         void *	     opaque,
				         uint32_t    sizeof_opaque 
				       );

    

    void register_func_hook( );
#endif
