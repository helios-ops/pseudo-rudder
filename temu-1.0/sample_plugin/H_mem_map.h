#ifndef H_MEM_MAP_H
    #define H_MEM_MAP_H

    #include <inttypes.h>


    typedef struct H_mem_mapping_entry
    {
	uint32_t  vaddr;
	uint32_t  con_value;
	uint32_t  size;

	struct H_mem_mapping_entry * next;

    }H_mem_mapping_entry_t, *PH_mem_mapping_entry;


    typedef struct H_mem_mapping_list
    {
	H_mem_mapping_entry_t * head;
	H_mem_mapping_entry_t * end;

	int		        count;
    }H_mem_mapping_list_t, *PH_mem_mapping_list;


    /* ---------------------------------------------------------------------------------- */
    void init_H_mem_map( );

    void free_H_mem_map( );

    void add_H_mem_map_entry( uint32_t addr,
			      uint32_t size,
			      uint32_t con_value
		  	    );


    
    H_mem_mapping_entry_t * find_H_mem_map_entry( uint32_t vaddr,
				              	  uint32_t size
					    	);
    /* ---------------------------------------------------------------------------------- */


#endif
