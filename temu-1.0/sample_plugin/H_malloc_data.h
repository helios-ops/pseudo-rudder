#ifndef H_MALLOC_DATA_H
    #define H_MALLOC_DATA_H

    #include <inttypes.h>

    typedef struct H_malloc_data
    {
	uint32_t addr;
	uint32_t size;
	
	struct H_malloc_data * next;
    }H_malloc_data_t, *PH_malloc_data_t;

    typedef struct H_malloc_data_list
    {
	H_malloc_data_t * head;
	H_malloc_data_t * end;

	int count;
    }H_malloc_data_list_t, *PH_malloc_data_list_t;

    
    void H_heap_data_list_init( );
    void add_entry_to_heap_data_list( uint32_t addr,
			   	      uint32_t size
			  	    );
    void delete_entry_from_heap_data_list(uint32_t addr);
    void heap_data_list_delete( );

    int Find_heap_entry_by_vaddr( uint32_t   vaddr,
				  uint32_t * heap_hlimit
			        );
#endif
