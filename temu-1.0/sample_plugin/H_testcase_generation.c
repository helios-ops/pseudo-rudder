#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <malloc.h>

#include "hc_interface.h"
#include "H_testcase_generation.h"

extern HVC HHui_VC;


#ifdef H_DEBUG_TEST

void dbg_check_byte_in_testcase_4_expr( uint32_t   byte_index,
					HExpr	   dst_expr,
					char *     filename
			      	      )
{
    char   buffer[1024];
    char * databuf = NULL;
    int    count   = 0;
    int    fd      = 0;

    int      var_count = 0;
    HExpr *  var_array = obtaint_stp_vars_array(&var_count);
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    HExpr    tmp_expr3 = NULL;
    HExpr    tmp_expr4 = NULL;

    uint32_t tmp_value = 0;

    int qresult = 0;
    HWholeCounterExample wce = NULL;

    int i = 0;
        
    // as it's for byte's calculation, just only cares for the 255 values.	   
    for(i = 0 ; i < 256; i = i + 1)
    {
	tmp_expr1 = vc_bvConstExprFromInt( HHui_VC,
					   8,
					   i
					 );
	tmp_expr2 = vc_eqExpr( HHui_VC,
			       var_array[byte_index],
			       tmp_expr1
			     );	
	// vc_DeleteExpr(tmp_expr1);

	tmp_expr3 = vc_andExpr( HHui_VC,
				dst_expr,
				tmp_expr2
			      );
	// vc_DeleteExpr(tmp_expr2);

	tmp_expr4 = vc_notExpr( HHui_VC,
				tmp_expr3
			      );
	// vc_DeleteExpr(tmp_expr3);

	vc_push(HHui_VC);
	qresult = vc_query( HHui_VC,
			    tmp_expr4
			  );
	if(qresult == 0)
	{
	    term_printf( "available value %d for var[%d]\n", 
			 i,
			 byte_index
		       );
	}// end of if(qresult)

	vc_pop(HHui_VC);
	// vc_DeleteExpr(tmp_expr4);
    }// end of for{i}

    if(var_array == NULL)
    {
        free(var_array);
    }// end of if(var_array)
}// end of dbg_check_byte_in_testcase_4_expr( )

void dbg_testcase_generate_4_expr( char * filename,
				   HExpr  path_expr
			         )
{
    char   buffer[1024];
    char * databuf = NULL;
    int    count   = 0;
    int    fd      = 0;

    int      var_count = 0;
    HExpr *  var_array = obtaint_stp_vars_array(&var_count); // var-exprs --- vc_varExpr( )
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    uint32_t tmp_value = 0;

    int qresult = 0;
    HWholeCounterExample wce = NULL;

    int i = 0;
    
    /*
    count = sprintf( buffer,
		     "./testcase/testcase_%d",
		     path_id
		   );   
    buffer[count] = '\0';
     */

    if(fd >= 0)
    {
	if(var_count > 0)
	{
	    databuf = (char *)malloc(sizeof(char) * var_count);

	    tmp_expr1 = vc_notExpr( HHui_VC,
				    path_expr
				  );
	    vc_push(HHui_VC);
	    qresult = vc_query( HHui_VC,
				tmp_expr1
			      );

	    if(qresult == 0)
	    {
	        umask(0);
	        fd = open( filename, // buffer,
		           (O_CREAT | O_RDWR),
		           (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		         );

		wce = vc_getWholeCounterExample(HHui_VC);

		for(i = 0; i < var_count; i = i + 1)
		{
		    tmp_expr2  = vc_getTermFromCounterExample( HHui_VC,
						               var_array[i],
						   	       wce
					         	     );		    	
		    databuf[i] = getBVUnsigned(tmp_expr2);

		    vc_DeleteExpr(tmp_expr2);
		}// end of for{i}

		write( fd,
	               databuf,
	               var_count
	             );
		close(fd);
	    }
	    else
	    {
		term_printf("dbg: fucking path_Expr testcase generation !\n");
	    }// end of if(qresult)

	    vc_pop(HHui_VC);	    	    
	    vc_DeleteExpr(tmp_expr1);

	    free(databuf);	    
	}// end of if(var_count)
    }// end of if(fd)


    if(var_array != NULL)
    {
	free(var_array);
    }// end of if(var_array)
}// end of H_testcase_generate_4_expr( )
#endif


void H_testcase_generate_4_expr( uint32_t path_id,
				 HExpr    path_expr
			       )
{
    char   buffer[1024];
    char * databuf = NULL;
    int    count   = 0;
    int    fd      = 0;

    int      var_count = 0;
    HExpr *  var_array = obtaint_stp_vars_array(&var_count);
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    uint32_t tmp_value = 0;

    int qresult = 0;
    HWholeCounterExample wce = NULL;

    int i = 0;
    
    count = sprintf( buffer,
		     "./testcase/testcase_%d",
		     path_id
		   );
    buffer[count] = '\0';
    
    if(fd >= 0)
    {
	if(var_count > 0)
	{
	    databuf = (char *)malloc(sizeof(char) * var_count);

	    tmp_expr1 = vc_notExpr( HHui_VC,
				    path_expr
				  );
	    vc_push(HHui_VC);
	    qresult = vc_query( HHui_VC,
				tmp_expr1
			      );

	    if(qresult == 0)
	    {
	        umask(0);
	        fd = open( buffer,
		           (O_CREAT | O_RDWR),
		           (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		         );

		wce = vc_getWholeCounterExample(HHui_VC);

		for(i = 0; i < var_count; i = i + 1)
		{
		    tmp_expr2  = vc_getTermFromCounterExample( HHui_VC,
						               var_array[i],
						   	       wce
					         	     );		    	
		    databuf[i] = getBVUnsigned(tmp_expr2);

		    vc_DeleteExpr(tmp_expr2);
		}// end of for{i}

		write( fd,
	               databuf,
	               var_count
	             );
		close(fd);
	    }// end of if(qresult)

	    vc_pop(HHui_VC);	    	    
	    vc_DeleteExpr(tmp_expr1);

	    free(databuf);	    
	}// end of if(var_count)
    }// end of if(fd)


    if(var_array != NULL)
    {
	free(var_array);
    }// end of if(var_array)
}// end of H_testcase_generate_4_expr( )





