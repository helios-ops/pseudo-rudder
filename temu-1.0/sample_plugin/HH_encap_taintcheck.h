#ifndef HH_ENCAP_TAINTCHECK_H

    #define HH_ENCAP_TAINTCHECK_H

    #include <inttypes.h>

    /*
    	   taintcheck_taint_virtmem,  // HHui_encap_taintcheck_taint_virtmem
    	   taintcheck_taint_register  // HHui_encap_taintcheck_taint_register
     */


    typedef struct HH_encap_tc_vaddr_entry
    {
	uint32_t vaddr;
	uint32_t size;
	
	struct HH_encap_tc_vaddr_entry * next;

    }HH_encap_tc_vaddr_entry_t, *PHH_encap_tc_vaddr_entry_t;


    typedef struct HH_encap_tc_vaddr_list
    {
	struct HH_encap_tc_vaddr_entry * head;
	struct HH_encap_tc_vaddr_entry * end;

	int count;
    }HH_encap_tc_vaddr_list_t, *PHH_encap_tc_vaddr_list;


    extern HH_encap_tc_vaddr_list_t h_encap_vaddr_tclist;


    /* -------------------------------------------------------------------------------------------------------------- */
    
    void HHui_init_tc_vaddr_list( );

    void HHui_delete_tc_vaddr_list( );

    void HHui_add_tainted_vaddr( uint32_t vaddr,
				 uint32_t size
			       );


    void HHui_encap_taintcheck_taint_virtmem( uint32_t  vaddr,
					      uint32_t  size,
					      uint64_t  taint,
					      uint8_t * records
					    );

    void HHui_encap_taintcheck_virtmem_register( );

    /* -------------------------------------------------------------------------------------------------------------- */


#endif
