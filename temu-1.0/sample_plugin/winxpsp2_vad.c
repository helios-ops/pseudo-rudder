#include <stdlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include "winxpsp2_vad.h"

#include "../TEMU_lib.h"
#include "../TEMU_main.h"

#include "H_test_config.h"

extern plugin_interface_t my_interface;

uint32_t WINDOWS_obtain_vad(void * my_EPROCESS)
{
    uint32_t vad_root = 0;

    TEMU_read_mem( ( (uint32_t)my_EPROCESS + 0x11c ),
		   4,
		   &vad_root
		 );

    return vad_root;       
}// end of WINDOWS_obtain_vad( )


#ifdef H_DEBUG_TEST
int sub_dbg_addr_is_in_vad_range( uint32_t   value,
				  uint32_t   vad_root,
			          uint32_t * start_addr,
			          uint32_t * end_addr
			        )
{   
    uint32_t vad_start_va   = 0;
    uint32_t vad_end_va     = 0;

    uint32_t vad_parentlink = 0;
    uint32_t vad_leftlink   = 0;
    uint32_t vad_rightlink  = 0;
    uint32_t vad_flag       = 0;

    // Reading guest-OS's VAD structure !
    /* ------------------------------------------------------------------------------- */
    TEMU_read_mem( ( (uint32_t)vad_root + VAD_STARTVA_OFFSET ),
		   4,
		   &vad_start_va
		 );
    vad_start_va = vad_start_va * 0x1000;
    

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_ENDVA_OFFSET ),
		   4,
		   &vad_end_va
		 );
    vad_end_va = vad_end_va + 1;
    vad_end_va = vad_end_va * 0x1000 - 1;

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_PARENTLINK_OFFSET ),
		   4,
		   &vad_parentlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_LEFTLINK_OFFSET ),
		   4,
		   &vad_leftlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_RIGHTLINK_OFFSET ),
		   4,
		   &vad_rightlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_FLAG_OFFSET ),
		   4,
		   &vad_flag
		 );

    if( (value >= vad_start_va) && 
	(value <= vad_end_va) 
      )
    {
	*start_addr = vad_start_va;
	*end_addr   = vad_end_va;
	return 1;
    }// end of if(value)

    if(vad_leftlink != 0)
    {
	if( sub_dbg_addr_is_in_vad_range( value,
					  vad_leftlink,
			          	  start_addr,
			          	  end_addr
			        	) != 0
	  )
	{
	    return 1;
	}// end of if(sub_dbg_addr_is_in_vad_range( ))	
    }// end of if(vad_leftlink)


    if(vad_rightlink != 0)
    {
	if( sub_dbg_addr_is_in_vad_range( value,
					  vad_rightlink,
			          	  start_addr,
			          	  end_addr
			        	) != 0
	  )
	{
	    return 1;
	}// end of if(sub_dbg_addr_is_in_vad_range( ))	
    }// end of if(vad_leftlink)
    /* ------------------------------------------------------------------------------- */
    // Reading guest-OS's VAD structure !    

    return 0;
}// end of sub_dbg_addr_is_in_vad_range( )


int dbg_addr_is_in_vad_range( uint32_t   value,
			      uint32_t * start_addr,
			      uint32_t * end_addr
			    )
{
    uint32_t vadroot = 0;
    my_interface.monitored_vad = my_interface.obtain_vad( (void *)(my_interface.p_eprocess));

    vadroot = my_interface.monitored_vad;
    return  sub_dbg_addr_is_in_vad_range( value,
				   	  vadroot,
			          	  start_addr,
			          	  end_addr
			                );
}// end of dbg_addr_is_in_vad_range( )


void sub_dbg_dump_vad_range( int      fd,
			     uint32_t vad_root
			   )
{   
    char buffer[50];
    int  count = 0;

    uint32_t vad_start_va   = 0;
    uint32_t vad_end_va     = 0;

    uint32_t vad_parentlink = 0;
    uint32_t vad_leftlink   = 0;
    uint32_t vad_rightlink  = 0;
    uint32_t vad_flag       = 0;

    // Reading guest-OS's VAD structure !
    /* ------------------------------------------------------------------------------- */
    TEMU_read_mem( ( (uint32_t)vad_root + VAD_STARTVA_OFFSET ),
		   4,
		   &vad_start_va
		 );
    vad_start_va = vad_start_va * 0x1000;
    

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_ENDVA_OFFSET ),
		   4,
		   &vad_end_va
		 );
    vad_end_va = vad_end_va + 1;
    vad_end_va = vad_end_va * 0x1000 - 1;

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_PARENTLINK_OFFSET ),
		   4,
		   &vad_parentlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_LEFTLINK_OFFSET ),
		   4,
		   &vad_leftlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_RIGHTLINK_OFFSET ),
		   4,
		   &vad_rightlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_FLAG_OFFSET ),
		   4,
		   &vad_flag
		 );
    if(fd >= 0)
    {
	count = sprintf( buffer,
			 "0x%x----0x%x\n",
			 vad_start_va,
			 vad_end_va
		       );
	buffer[count] = '\0';

	write( fd,
	       buffer,
	       count
	     );
    }// end of if(fd)

    if(vad_leftlink != 0)
    {
	sub_dbg_dump_vad_range( fd,
			        vad_leftlink
			      );
    }// end of if(vad_leftlink)


    if(vad_rightlink != 0)
    {
	sub_dbg_dump_vad_range( fd,
			        vad_rightlink
			      );
    }// end of if(vad_leftlink)
    /* ------------------------------------------------------------------------------- */
    // Reading guest-OS's VAD structure !    

    return 0;
}// end of sub_dbg_addr_is_in_vad_range( )


void dbg_dump_vad_range( )
{
    uint32_t vadroot = 0;
    int fd = -1;

    my_interface.monitored_vad = my_interface.obtain_vad( (void *)(my_interface.p_eprocess));
    vadroot = my_interface.monitored_vad;

    umask(0);

    fd = open( "vad_log",
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    sub_dbg_dump_vad_range( fd,
			    vadroot
			  );

    close(fd);    
}// end of dbg_dump_vad_range( )
#endif


int build_symaddr_invalid_constraint( HVC        hvc,
				      HExpr      symaddr_expr,
	  	            	      int        access_mode,        /* 1 -- read; 2 -- write; 4 -- execute */
				      uint32_t * vad_root_ptr,
				      HExpr *    out_of_range_expr,
				      HExpr *    invalid_access_expr
			      	    )
{
    uint32_t vad_start_va   = 0;
    uint32_t vad_end_va     = 0;
    uint32_t vad_parentlink = 0;
    uint32_t vad_leftlink   = 0;
    uint32_t vad_rightlink  = 0;
    uint32_t vad_flag	    = 0;


    HExpr    left_invalid_access_expr = NULL;
    HExpr    left_out_of_range_expr   = NULL;
    int      left_ret   = 0;

    HExpr    right_invalid_access_expr = NULL;
    HExpr    right_out_of_range_expr   = NULL;
    int      right_ret  = 0;

    uint32_t flag	= 0;

    HExpr    tmp_expr1  = NULL;
    HExpr    tmp_expr2  = NULL;

    HExpr    tmp_expr3  = NULL;
    HExpr    tmp_expr4  = NULL;

    HExpr    tmp_expr5  = NULL;
    

    HExpr    invalid_low_expr  = NULL;
    HExpr    invalid_high_expr = NULL;

    // HExpr    invalid_range_expr = NULL;
        
    my_interface.monitored_vad = my_interface.obtain_vad( (void *)(my_interface.p_eprocess));
    uint32_t vad_root = *vad_root_ptr;
    // uint32_t vad_root = my_interface.monitored_vad;

    if(vad_root == NULL)
    {
	return 0;
    }// end of if( )


    // Reading guest-OS's VAD structure !
    /* ------------------------------------------------------------------------------- */
    TEMU_read_mem( ( (uint32_t)vad_root + VAD_STARTVA_OFFSET ),
		   4,
		   &vad_start_va
		 );
    vad_start_va = vad_start_va * 0x1000;
    

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_ENDVA_OFFSET ),
		   4,
		   &vad_end_va
		 );
    vad_end_va = vad_end_va + 1;
    vad_end_va = vad_end_va * 0x1000 - 1;

    /*
    term_printf( "vad_start_va = 0x%x, vad_end_va = 0x%x!\n",
		 vad_start_va,
		 vad_end_va
	       );
    */

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_PARENTLINK_OFFSET ),
		   4,
		   &vad_parentlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_LEFTLINK_OFFSET ),
		   4,
		   &vad_leftlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_RIGHTLINK_OFFSET ),
		   4,
		   &vad_rightlink
		 );

    TEMU_read_mem( ( (uint32_t)vad_root + VAD_FLAG_OFFSET ),
		   4,
		   &vad_flag
		 );
    /* ------------------------------------------------------------------------------- */
    // Reading guest-OS's VAD structure !

    
    left_ret  = build_symaddr_invalid_constraint( hvc,
						  symaddr_expr,
	  	            	      		  access_mode,  /* 1 -- read; 2 -- write; 4 -- execute */
				      		  &vad_leftlink, // vad_root->left_link,
				     		  &left_out_of_range_expr,
				     		  &left_invalid_access_expr
			      	    		);

    right_ret = build_symaddr_invalid_constraint( hvc,
						  symaddr_expr,
	  	            	      		  access_mode,   /* 1 -- read; 2 -- write; 4 -- execute */
				      		  &vad_rightlink, // vad_root->right_link,
						  &right_out_of_range_expr,
						  &right_invalid_access_expr
			      	    		);
    
    // invalid range constraint
    /* ----------------------------------------------------------------------------------------------------- */
    tmp_expr1 = vc_bvConstExprFromInt( hvc,
				       32,
				       vad_start_va // vad_root->start_va
				     );

    invalid_low_expr = vc_bvLtExpr( hvc,
				    symaddr_expr,
				    tmp_expr1
				  );       

    // vc_DeleteExpr(tmp_expr1);

    tmp_expr2 = vc_bvConstExprFromInt( hvc,
				       32,
				       vad_end_va // vad_root->end_va
				     );

    invalid_high_expr = vc_bvGtExpr( hvc,
				     symaddr_expr,
				     tmp_expr2
				   );

    // vc_DeleteExpr(tmp_expr2);


    tmp_expr1 = vc_orExpr( hvc,
		           invalid_low_expr,
			   invalid_high_expr
			 );
/*
    vc_DeleteExpr(invalid_low_expr);
    vc_DeleteExpr(invalid_high_expr);
 */

    *out_of_range_expr = tmp_expr1;

    if(left_ret != 0)
    {
	tmp_expr2 = vc_andExpr( hvc,
				tmp_expr1,
				left_out_of_range_expr
			      );

        *out_of_range_expr = tmp_expr2;
    }// end of if( )

    if(right_ret != 0)
    {
	*out_of_range_expr = vc_andExpr( hvc,
					 *out_of_range_expr,
					 right_out_of_range_expr
				       );	
    }// end of if( )

/*    
    if( (left_ret != 0) ||
	(right_ret != 0)
      )
    {
        vc_DeleteExpr(tmp_expr1);
    }// end of if( )


    if( (left_ret != 0) &&
	(right_ret != 0)
      )
    {
	vc_DeleteExpr(tmp_expr2);
    }// end of if( )


    if(left_ret != 0)
    {
	vc_DeleteExpr(left_out_of_range_expr);
    }// end of if( )


    if(right_ret != 0)
    {
	vc_DeleteExpr(right_out_of_range_expr);
    }// end of if( )    
*/
    /* ----------------------------------------------------------------------------------------------------- */
    // invalid range constraint



    // invalid access-mode constraint
    /* ----------------------------------------------------------------------------------------------------- */
    // read !
    if((access_mode & 0x1) != 0)
    {
        flag = (vad_flag & PAGE_READONLY) || (vad_flag & PAGE_READWRITE) ;
    }// end of if( )


    // write !
    if((access_mode & 0x2) != 0)
    {
	flag = (vad_flag & PAGE_READWRITE) || (vad_flag & PAGE_WRITECOPY) || (vad_flag & PAGE_EXECUTE_WRITECOPY);
    }// end of if( )

   
    // we got an invalid LA-range for this access !
    if(flag == 0)
    {
	tmp_expr1 = vc_bvConstExprFromInt( hvc,
					   32,
					   (uint32_t)(vad_start_va)
					 );

	tmp_expr2 = vc_bvConstExprFromInt( hvc,
					   32,
					   (uint32_t)(vad_end_va)
					 );

        // symaddr >= low_addr
   	tmp_expr3 = vc_bvGeExpr( hvc,
				 symaddr_expr,
				 tmp_expr1
			       );
	/*
	tmp_expr3 = vc_notExpr( hvc,
				vc_bvBoolExtract( hvc,
						  tmp_expr3,
						  0
						)
			      );
	*/
	vc_DeleteExpr(tmp_expr1);


	// symaddr <= low_addr
   	tmp_expr4 = vc_bvLeExpr( hvc,
				 symaddr_expr,
				 tmp_expr2
			       );
	/*
	tmp_expr4 = vc_notExpr( hvc,
				vc_bvBoolExtract( hvc,
						  tmp_expr4,
						  0
						)
			      );
	*/
	vc_DeleteExpr(tmp_expr2);
	
	tmp_expr1 = vc_andExpr( hvc,
				tmp_expr3,
				tmp_expr4
			      );
	*invalid_access_expr = tmp_expr1;

	vc_DeleteExpr(tmp_expr3);
	vc_DeleteExpr(tmp_expr4);
    }// end of if(flag == 0)


    if(left_invalid_access_expr != NULL)
    {
	if(flag == 0)
	{
	    *invalid_access_expr = vc_orExpr( hvc,
					      tmp_expr1,
					      left_invalid_access_expr
					    );
	}
	else 
	{
	    *invalid_access_expr = left_invalid_access_expr;
	}// end of if( )
    }// end of if( )


    if(right_invalid_access_expr != NULL)
    {
	if(*invalid_access_expr != NULL)
	{
	    *invalid_access_expr = vc_orExpr( hvc,
					      *invalid_access_expr,
					      right_invalid_access_expr
					    );
	}
	else
	{
	    *invalid_access_expr = right_invalid_access_expr;
	}// end of if( )
    }// end of if( )


    // tmp_expr1
    if( (right_invalid_access_expr != NULL) &&
	(left_invalid_access_expr != NULL) &&
	(flag == 0)
      )
    {
	vc_DeleteExpr(tmp_expr1);
	vc_DeleteExpr(left_invalid_access_expr);
	vc_DeleteExpr(right_invalid_access_expr);	
    }
    else if( (right_invalid_access_expr != NULL) &&
	     (left_invalid_access_expr != NULL)
	   )
    {
	vc_DeleteExpr(left_invalid_access_expr);
	vc_DeleteExpr(right_invalid_access_expr);
    }
    else if( (left_invalid_access_expr != NULL) &&
	     (flag == 0)
	   )
    {
	vc_DeleteExpr(tmp_expr1);	
	vc_DeleteExpr(left_invalid_access_expr);
    }
    else if( (right_invalid_access_expr != NULL) &&
	     (flag == 0)
	   )
    {
	vc_DeleteExpr(tmp_expr1);	
	vc_DeleteExpr(right_invalid_access_expr);	
    }// end of if( )
    /* ----------------------------------------------------------------------------------------------------- */
    // invalid access-mode constraint


    return 1;
}// end of build_symaddr_invalid_constraint( )




