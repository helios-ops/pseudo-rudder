#ifndef H_FUNC_DUMP_STACKPARAM_H
    #define H_FUNC_DUMP_STACKPARAM_H


    void func_dump_stackparams( uint32_t   func_addr,
			        uint32_t   callsite_id,
			        uint8_t  * buf,
			        uint32_t   length,
				uint64_t   tcbmap
			      );

    
    void func_load_stackparams( uint32_t   func_addr,
			        uint32_t   callsite_id,
			        uint8_t ** ret_buf,
			        uint32_t * length,
				uint64_t * tcbmap
			      );

#endif
