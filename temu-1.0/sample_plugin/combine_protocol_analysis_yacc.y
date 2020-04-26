%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "H_test_config.h"
#include "h_atoi.h"
#include "combine_protocol_analysis.h"
#include "../TEMU_main.h"

#ifdef H_USE_PROTOCOL_ANALYSIS

static int   total_len_count	      = 0;

// record byte-sequence for each len-domain 
// [ 2 dimension array with the 2nd dimension holding only 2 elements ]
static int * total_len_domains      = NULL;
static int   current_total_size     = 200;

static int   current_len_domain_idx = -1;
static int   current_byte_idx	    = -1;

extern plugin_interface_t my_interface;

extern int h_strrstr( char * str,
	 	      char   chr
	     	    );

static file_protocol_list_t h_file_proto_list;

void file_protocol_list_init( )
{
    h_file_proto_list.head  = NULL;
    h_file_proto_list.end   = NULL;
    h_file_proto_list.count = 0;
}// end of file_protocol_list_init( )

void file_proto_list_delete( )
{
    file_protocol_t * entry = h_file_proto_list.head;
    while(entry != NULL)
    {
	entry = entry->next;
	free((h_file_proto_list.head)->len_domains);
	free((h_file_proto_list.head)->filename);

	free(h_file_proto_list.head);

	h_file_proto_list.head = entry;
    }// end of while{entry}

    h_file_proto_list.head  = NULL;
    h_file_proto_list.end   = NULL;
    h_file_proto_list.count = 0;
}// end of file_proto_list_delete( )


static int fetch_len_domain_by_filename( char * filename,
					 int ** len_domains,
					 int  * count
				       )
{
    file_protocol_t * entry = h_file_proto_list.head;
    while(entry != NULL)
    {
	if( strcmp( filename,
		    entry->filename
		  ) == 0
	  )
	{
	    *len_domains = entry->len_domains;
	    *count	 = entry->len_domain_count;
	    return 1;
	}// end of if(strcmp( ))

	entry = entry->next;
    }// end of while{entry}

    return 0;
}// end of fetch_len_domain_by_filename( )


static void addentry_2_file_proto_list( char * filename,
					int  * len_domain,
				 	int    count 
			       	      )
{
    file_protocol_t * entry = (file_protocol_t *)malloc(sizeof(file_protocol_t));
    int idx = h_strrstr( filename,
	 	      	 '\\'
	     	       );
    int len = 0;

    entry->len_domains 	    = len_domain;
    entry->len_domain_count = count;
    entry->next		    = NULL;
    len = strlen( (filename + idx + 1) );
    entry->filename	    = (char *)malloc(sizeof(char) * (len + 1));
    strcpy( entry->filename,
	    (filename + idx + 1)
	  );
    (entry->filename)[len] = '\0';

    if(h_file_proto_list.head == NULL)
    {
	h_file_proto_list.head = entry;
	h_file_proto_list.end  = entry;
    }
    else
    {
	(h_file_proto_list.end)->next = entry;
	h_file_proto_list.end	      = entry;
    }// end of if(h_file_proto_list.head)

    h_file_proto_list.count = h_file_proto_list.count + 1;
}// end of addentry_2_file_proto_list( )


static void yyerror(const char * str)
{
/*
    fprintf( stderr,
	     "error: %s\n",
	     str
	   );
 */
    term_printf("yacc: HHui fuck-parsing file!\n");
}// end of yyerror( )


void h_TEMU_build_protocol_analysis_util( )
{
    my_interface.proto_util = (protocol_analysis_util_t *)malloc(sizeof(protocol_analysis_util_t));

    (my_interface.proto_util)->h_protocol_analysis_init = protocol_analysis_init;
    // (my_interface.proto_util)->h_protocol_analysis_free = protocol_analysis_free;
}// end of h_TEMU_build_protocol_analysis_util( )

/*
void protocol_analysis_free( )
{
    int i = 0;

    if(total_len_domains != NULL)
    {
	free(total_len_domains);
    }// end of if(total_len_domains)

    total_len_domains = NULL;
    total_len_count   = 0;
}// end of protocol_analysis_free( )
*/

/* category_id:
   0 --- file-source
        sub_category_id: 
	0 --- midi file
   
 */
void protocol_analysis_init( int    category_id,
			     int    sub_category_id,
			     char * filename,
			     int *  h_total_len_count,  // OUTPUT the total count of the length domain in the target-file
			     int ** h_total_len_domains // OUTPUT the byte_sequence for each len_domain
			   )
{
    FILE * fp     = NULL;    
    char   buffer[100];

    char * str   = NULL;
    int    idx   = -1;

    int    count = 0;
   
    strcpy( buffer,
	    "./input_protocol/"
	  );
    buffer[17] = '\0';
        
    switch(category_id)
    {
	case 0: // file-input
	{
	    strcpy( buffer + 17,
		    "file_protocol/"
		  );
	    buffer[17 + 14] = '\0';

	    if(filename != NULL)
	    {
		idx = h_strrstr( filename,
	 	      		 '\\'
	     	    	       );

		count = sprintf( buffer + 31,
			 	 "%s_format",
				 (filename + idx + 1)
			       );
		buffer[31 + count] = '\0';
	    }// end of if(filename)
	    break;
	}
    }// end of switch{category_id}

    // checks if this file has been previously parsed.
    if( fetch_len_domain_by_filename( (filename + idx + 1),
				      h_total_len_domains,
				      h_total_len_count
				    ) == 1
      )
    {
	return;
    }// end of if(fetch_len_domain_by_filename( ))

    fp = fopen( buffer,
		"r"
	      );
    if(fp == NULL)
    {
	return;
    }// end of if(fp)

    total_len_domains = (int *)malloc(sizeof(int) * 200);

    yyrestart(fp);
    yyparse( );    

    fclose(fp);

    // OUTPUT the total count of the length domain in the target-file
    *h_total_len_count   = total_len_count;

    // OUTPUT the byte_sequence for each len_domain
    *h_total_len_domains = total_len_domains;

    addentry_2_file_proto_list( (filename + idx + 1),
				total_len_domains,
				total_len_count
			      );
}// end of protocol_analysis_init( )

#endif

%}


%token LEN_DOMAIN TOKENIZER BYTE_COUNT SEMICOLON NUMBER SEPARATOR

%%

header: 
	LEN_DOMAIN TOKENIZER NUMBER TOKENIZER statements
	{
	#ifdef H_USE_PROTOCOL_ANALYSIS
	    total_len_count   = h_atoint($3);
	    // total_len_domains = (int *)malloc(sizeof(int) * total_len_count * 2);
	    free($3);
	    // total_len_domain_lens = (int *)malloc(sizeof(int) * total_len_count);
	#endif
	}
	;

statements: |
	    statement statements
	    ;

statement: BYTE_COUNT TOKENIZER NUMBER TOKENIZER terms
	   {
	   /*
	   #ifdef H_USE_PROTOCOL_ANALYSIS
	       current_len_domain_idx = current_len_domain_idx + 1;
	       current_byte_idx	      = -1;
	   #endif
	   */
	   }
	   ;

terms:
      | term terms
	;


term: NUMBER SEMICOLON 	   
      {	  
      #ifdef H_USE_PROTOCOL_ANALYSIS
       	  current_byte_idx = current_byte_idx + 1;
	  if(current_total_size == current_byte_idx)
	  {
	      current_total_size = current_total_size + 200;
	      total_len_domains = realloc( total_len_domains,
					   current_total_size
					 );
	  }// end of if(current_byte_idx)
	  
	  total_len_domains[current_byte_idx] = h_atoint($1);

	  free($1);
      #endif
      }
      ;

%%
