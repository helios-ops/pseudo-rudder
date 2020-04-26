#include <sys/stat.h>
// #include <apue.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "hc_interface.h"
#include "../TEMU_main.h"

extern HVC  HHui_VC;

static int error_total_id = 0;

static char ERROR_file_name[1000];

static int API_errors = 0;

#ifndef APIHOOKING_ERROR_CATEGORY_COUNT
    #define APIHOOKING_ERROR_CATEGORY_COUNT 2
    /* err_id:
	 0 --- malloc( )
	 1 --- strcpy( )
     */
#endif

static int APIHooking_errors[APIHOOKING_ERROR_CATEGORY_COUNT];


// record errors found during API hooking.
// void APIHooking_record_ERROR_2file(char * str_info)
void APIHooking_record_ERROR_2file( HExpr err_expr,
				    int   category_id
				  )
{
    char * str_info = exprString(err_expr);
    int fd = -1; 
    int i  = 0;

    // first time initialization !
    if(API_errors == 0)
    {
	for(i = 0; i < APIHOOKING_ERROR_CATEGORY_COUNT; i = i + 1)
	{
	    APIHooking_errors[i] = 0;	  
	}// end of for{i}
	
	// APIHooking_error_pathConstraint
	ERROR_file_name[0]  = '.';
	ERROR_file_name[1]  = '/';
	ERROR_file_name[2]  = 'A';
	ERROR_file_name[3]  = 'P';
	ERROR_file_name[4]  = 'I';
	ERROR_file_name[5]  = 'H';
	ERROR_file_name[6]  = 'o';
	ERROR_file_name[7]  = 'o';
	ERROR_file_name[8]  = 'k';
	ERROR_file_name[9]  = 'i';
	ERROR_file_name[10] = 'n';
	ERROR_file_name[11] = 'g';
	ERROR_file_name[12] = '_';
	ERROR_file_name[13] = 'e';
	ERROR_file_name[14] = 'r';
	ERROR_file_name[15] = 'r';
	ERROR_file_name[16] = 'o';
	ERROR_file_name[17] = 'r';
	ERROR_file_name[18] = '_';
	ERROR_file_name[19] = 'P';
	ERROR_file_name[20] = 'a';
	ERROR_file_name[21] = 't';
	ERROR_file_name[22] = 'h';
	ERROR_file_name[23] = 'C';
	ERROR_file_name[24] = 'o';
	ERROR_file_name[25] = 'n';
	ERROR_file_name[26] = 's';
	ERROR_file_name[27] = 't';
	ERROR_file_name[28] = 'r';
	ERROR_file_name[29] = 'a';
	ERROR_file_name[30] = 'i';
	ERROR_file_name[31] = 'n';
	ERROR_file_name[32] = 't';
	ERROR_file_name[33] = '/';
	ERROR_file_name[34] = '\0';
    }// end of if(API_errors)

    // IRSYMEXE_error_seq_num = IRSYMEXE_error_seq_num + 1;
    API_errors = API_errors + 1;
    APIHooking_errors[category_id] = APIHooking_errors[category_id] + 1;
    int num_len = sprintf( (ERROR_file_name + 34),
			   "pc_%d_%d",
			   category_id,
			   APIHooking_errors[category_id]
	   		 );
    ERROR_file_name[34 + num_len] = '\0';

    umask(0);
    fd = open( ERROR_file_name,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );

    if(fd != -1)
    {
	write( fd, 
	       str_info,
 	       strlen(str_info)
	     );

	close(fd);
    }// end of if( )

    free(str_info);

    // now generate the corresponding testcase !
    H_APIHooking_error_testcase_generate_4_expr( err_expr,
			    		         category_id,
				      		 APIHooking_errors[category_id]
			       	     	       );    

}// end of record_ERROR_2file( )


void H_TEMU_printExpr(void * expr, int id)
{
    char * str = exprString((HExpr)expr);
    term_printf( "TEMU_expr : %s, equality = %d \n\n",
		 str,
		 strcmp( "func_10001020_stack_0 ",
			 str
		       )
	       );

    if(id == 0)
    {
        if( strcmp( "func_10001020_stack_0 ",
	  	    str
	          ) == 0
          )
        {
	    term_printf("func_10001020_stack_0 to be substituted !\n");
        }// end of if(strcmp)
    }// end of if(id)

    if(id == 1)
    {    
        if( strstr( str,
		    "TRUE"	   	    
	          ) != NULL
          )
        {
	    term_printf( "substituted expr is %s\n",
			 str
		       );
        }// end of if(strcmp)
    }// end of if(id)

    free(str);
}// end of H_TEMU_printExpr( )


// testcase generation for errors found during API-Hooking.
void H_APIHooking_error_testcase_generate_4_expr( HExpr    path_expr,
				    	          uint32_t category_id, 
				      		  int	   local_id
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
    // error_total_id = error_total_id + 1;


    count = sprintf( buffer,
		     "./APIHooking_error_testcase/testcase_%d_%d",
		     category_id,
		     local_id // error_total_id		     
		   );
    buffer[count] = '\0';

    fd = open( buffer,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    
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
	    }// end of if(qresult)

	    vc_pop(HHui_VC);	    	    
	    vc_DeleteExpr(tmp_expr1);

	    write( fd,
	           databuf,
	           var_count
	         );

	    free(databuf);
	    
	}// end of if(var_count)

	close(fd);
    }// end of if(fd)


    if(var_array != NULL)
    {
	free(var_array);
    }// end of if(var_array)
}// end of H_APIHooking_error_testcase_generate_4_expr( )



// testcase generation for errors found during IR-SYMEXE.
void H_IRSYMEXE_error_testcase_generate_4_expr( HExpr    path_expr,
				    	        uint32_t category_id,
				      		int	 local_id
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

    char * tmp_str = NULL;

    int qresult = 0;
    HWholeCounterExample wce = NULL;

    int i = 0;
    // error_total_id = error_total_id + 1;

    count = sprintf( buffer,
		     "./IRSYMEXE_error_testcase/testcase_%d_%d",
		     category_id,
		     local_id // error_total_id		     
		   );
    buffer[count] = '\0';

    fd = open( buffer,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    
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
		wce = vc_getWholeCounterExample(HHui_VC);

		for(i = 0; i < var_count; i = i + 1)
		{
		    tmp_expr2  = vc_getTermFromCounterExample( HHui_VC,
						               var_array[i],
						   	       wce
					         	     );		    	
		    databuf[i] = getBVUnsigned(tmp_expr2);

		    tmp_str = exprString(var_array[i]);
		    term_printf( "[%d] -- %s -- %x\n",
				 i,
				 tmp_str,
				 databuf[i]
			       );
		    free(tmp_str);

		    vc_DeleteExpr(tmp_expr2);
		}// end of for{i}
	    }// end of if(qresult)

	    vc_pop(HHui_VC);	    	    
	    vc_DeleteExpr(tmp_expr1);

	    write( fd,
	           databuf,
	           var_count
	         );

	    free(databuf);
	    
	}// end of if(var_count)

	close(fd);
    }// end of if(fd)


    if(var_array != NULL)
    {
	free(var_array);
    }// end of if(var_array)
}// end of H_IRSYMEXE_error_testcase_generate_4_expr( )


