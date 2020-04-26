#ifndef H_WINXPSP2_VAD_H

    #define H_WINXPSP2_VAD_H

    #include <inttypes.h>
    #include "hc_interface.h"

    #include "H_test_config.h"

    typedef struct H_VAD
    {
        uint32_t start_va;
	uint32_t end_va;

	struct H_VAD * parent_link;
	struct H_VAD * left_link;
	struct H_VAD * right_link;

	uint32_t flag;

    }H_VAD_t, *PH_VAD_t;

    #define VAD_STARTVA_OFFSET      0
    #define VAD_ENDVA_OFFSET	    4
    #define VAD_PARENTLINK_OFFSET   8
    #define VAD_LEFTLINK_OFFSET	    12
    #define VAD_RIGHTLINK_OFFSET    16
    #define VAD_FLAG_OFFSET    	    20



/*  orginal definations deleted by HHui at August 22nd, 2011
    
    #define MEM_IMAGE		    0x001
    #define MEM_PRIVATE 	    0x800

    #define PAGE_READONLY     	    (0x10)
    #define PAGE_READWRITE    	    (0x40)
    #define PAGE_WRITECOPY    	    (0x50)
    #define PAGE_EXECUTE      	    (0x20)
    #define PAGE_EXECUTE_READ 	    (0x30)
    #define PAGE_EXECUTE_READ_WRITE (0x60)
    #define PAGE_EXECUTE_WRITECOPY  (0x70)   
 */
   
    #define PAGE_READONLY     	    (0x1*0x1000000)
    #define PAGE_READWRITE    	    (0x4*0x1000000)
    #define PAGE_WRITECOPY    	    (0x5*0x1000000)
    #define PAGE_EXECUTE      	    (0x2*0x1000000)
    #define PAGE_EXECUTE_READ 	    (0x3*0x1000000)
    #define PAGE_EXECUTE_READ_WRITE (0x6*0x1000000)
    #define PAGE_EXECUTE_WRITECOPY  (0x7*0x1000000)


    uint32_t WINDOWS_obtain_vad(void * my_EPROCESS);
    
    int build_symaddr_invalid_constraint( HVC        hvc,
					  HExpr      symaddr_expr,
	  	            	          int        access_mode,      /* 1 -- read; 2 -- write; 4 -- execute */
				          uint32_t * vad_root,
				          HExpr *    out_of_range_expr,
				          HExpr *    invalid_access_expr
			      	        );


    typedef int (*BUILD_SYMADDR_INVALID_CONSTRAINT)( HVC      hvc,
						     HExpr    symaddr_expr,
	  	            	        	     int      access_mode,  /* 1 -- read; 2 -- write; 4 -- execute */
						     uint32_t vad_root,
				         	     HExpr *  out_of_range_expr,
				          	     HExpr *  invalid_access_expr
			      	        	   );

    #ifdef H_DEBUG_TEST
    int dbg_addr_is_in_vad_range( uint32_t   value,
			          uint32_t * start_addr,
			          uint32_t * end_addr
			        );
#endif

#endif









