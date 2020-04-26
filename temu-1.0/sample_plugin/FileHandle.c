#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "FileHandle.h"

#include "../TEMU_lib.h"
#include "../TEMU_main.h"
#include "../sample_plugin/H_test_config.h"

extern plugin_interface_t my_interface;


int h_strrstr( char * str,
	       char   chr
	     )
{
    int len = strlen(str);
    int i   = 0;

    for(i = len - 1; i >= 0; i = i - 1)
    {
	if(str[i] == chr)
   	{
	    return i;
	}// end of if(str[i])
    }// end of for{i}

    return -1;
}// end of if()


// For ordinary files
/* ================================================================================================================== */
static file_handle_entry_list_t fhe_list;

// files on which we would not monitor !
static char str_file_filtered[ ] = { NULL
				   };


void init_filehandle_entry_list( )
{
    fhe_list.head  = NULL;
    fhe_list.end   = NULL;

    fhe_list.count = 0;
}// end of init_filehandle_entry_list( )


void delete_filehandle_entry_list( )
{
    Pfile_handle_entry_t entry = fhe_list.head;
    while(entry != NULL)
    {
	fhe_list.head = (fhe_list.head)->next;

	free(entry->fname);
	free(entry);

	entry = fhe_list.head;
    }// end of while{entry}

}// end of delete_filehandle_entry_list( )


// called when API-hook Readfile( ) is invoked
int ascii_add_filehandle_to_list( uint32_t name,   
			     // just string's virtual address in the guest-OS, so to obtain the content of the string I have to TEMU_read_mem( ) it !
			    	  int      fd
			        )
{
    int  i   = 0;
    int  j   = 0;
    int  idx = 0;

#ifdef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
    int  is_interested = 0;
#endif

    char str_namebyte = 0;
    char temp_bytes[256];

    uint32_t str_name_addr  = name;

    Pfile_handle_entry_t entry = NULL;

    do
    {
        TEMU_read_mem( str_name_addr,
		       1,
		       &str_namebyte
		     );
	if(str_namebyte != (char)0)
	{
	    temp_bytes[i] = str_namebyte;
	    i = i + 1;
	    term_printf("%c", temp_bytes[i]);
	}// end of if( )
	str_name_addr = str_name_addr + 1;

    }while(str_namebyte != (char)0);

    temp_bytes[i] = (char)0 ;    

/* here, we check whether or not the file current ReadFile( ) cares is an interested source.
   Only true should we hook the return point of ReadFile( ) so as to introduce taints to the 
   target program.
 */
#ifdef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
    if(my_interface.interested_file_names != NULL)
    {
	// this is a test for ASCII filename.
	/* ----------------------------------------------------------------- */
	idx = h_strrstr( temp_bytes,
		         '\\'
		       );
	if(idx < 0)
	{
	    idx = 0;
	}// end of if(idx)

	for(j = 0; j < my_interface.interested_file_count; j = j + 1)
	{
	    if( strcmp( (my_interface.interested_file_names)[j],
		        (temp_bytes + idx + 1)
		      ) == 0
	      )
	    {
		is_interested = 1;
		break;
	    }// end of if(strcmp())	    
	}// end of for{i}
	/* ----------------------------------------------------------------- */
    }// end of if(temu_plugin)

    if(is_interested == 0)
    {
	return 0;
    }// end of if(is_interested)
#endif

    entry	   = (Pfile_handle_entry_t)malloc(sizeof(file_handle_entry_t));
    entry->fd      = fd;
    entry->foffset = 0;

    // i = 1;
    entry->fname  = (char *)malloc(sizeof(char) * (i+1));
    // entry->fname[0] = 'a';

    strcpy( entry->fname, 
	    temp_bytes
	  ); 

    *( (char *)(entry->fname) + i ) = (char)0;

    term_printf( "[tid:%x] --- OpenFile( ) --- name = %s, fd = %d, length = %d\n",
		 get_current_tid( ),
		 entry->fname,
		 fd,
		 i
	       );

    entry->next = NULL;

    if(fhe_list.head == NULL)
    {
	fhe_list.head = entry;
	fhe_list.end  = entry;
    }
    else
    {
	(fhe_list.end)->next = entry;
	fhe_list.end = entry;
    }// end of if( )
    fhe_list.count = fhe_list.count + 1;

    return 1;
}// end of ascii_add_filehandle_to_list( )





/* HHui Fixme TODO: a complete handing routine for unicode VS ascii comparing...
   		    As here I only handle those English ascii words' unicodes'
		    interpretation.
 */
// called when API-hook Readfile( ) is invoked
int unicode_add_filehandle_to_list( uint32_t name,   
			 	    // just string's virtual address in the guest-OS, so to obtain the content of the 					    // string I have to TEMU_read_mem( ) it !
			   	    int      fd
			  	  )
{
    int  i   = 0;
    int  j   = 0;
    int  idx = 0;

#ifdef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
    int  is_interested = 0;
#endif

    unsigned short str_namebyte = 0;
    char temp_bytes[256];

    uint32_t str_name_addr  = name;

    Pfile_handle_entry_t entry = NULL;

    do
    {
        TEMU_read_mem( str_name_addr,
		       2,
		       &str_namebyte
		     );
	if(str_namebyte != (unsigned short)0)
	{
	    // here only cares for those English asciis' unicodes' interpretation.
	    temp_bytes[i] = *( (char *)(&str_namebyte) );
	    i = i + 1;
	    // term_printf("%c", temp_bytes[i]);
	}// end of if( )
	str_name_addr = str_name_addr + 2;

    }while(str_namebyte != (unsigned short)0);

    temp_bytes[i] = (char)0 ;
    term_printf( "unicode_filename: %s\n",
		 temp_bytes
	       );

/* here, we check whether or not the file current ReadFile( ) cares is an interested source.
   Only true should we hook the return point of ReadFile( ) so as to introduce taints to the 
   target program.
 */
#ifdef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
    if(my_interface.interested_file_names != NULL)
    {
	// this is a test for ASCII filename.
	/* ----------------------------------------------------------------- */
	idx = h_strrstr( temp_bytes,
		         '\\'
		       );
	if(idx < 0)
	{
	    idx = 0;
	}// end of if(idx)

	for(j = 0; j < my_interface.interested_file_count; j = j + 1)
	{
	    if( strcmp( (my_interface.interested_file_names)[j],
		        (temp_bytes + idx + 1)
		      ) == 0
	      )
	    {
		is_interested = 1;
		break;
	    }// end of if(strcmp())	    
	}// end of for{i}
	/* ----------------------------------------------------------------- */
    }// end of if(temu_plugin)

    if(is_interested == 0)
    {
	return 0;
    }// end of if(is_interested)
#endif

    entry	   = (Pfile_handle_entry_t)malloc(sizeof(file_handle_entry_t));
    entry->fd      = fd;
    entry->foffset = 0;

    // i = 1;
    entry->fname  = (char *)malloc(sizeof(char) * (i+1));
    // entry->fname[0] = 'a';

    strcpy( entry->fname, 
	    temp_bytes
	  ); 

    *( (char *)(entry->fname) + i ) = (char)0;

    term_printf( "[tid:%x] --- name = %s, fd = %d, length = %d --- ",
		 get_current_tid( ),
		 entry->fname,
		 fd,
		 i
	       );

    entry->next = NULL;

    if(fhe_list.head == NULL)
    {
	fhe_list.head = entry;
	fhe_list.end  = entry;
    }
    else
    {
	(fhe_list.end)->next = entry;
	fhe_list.end = entry;
    }// end of if( )
    fhe_list.count = fhe_list.count + 1;

    return 1;
}// end of unicode_add_filehandle_to_list( )


void add_filehandle_to_list( uint32_t name,
			     int      fd
			   )
{
    if( ascii_add_filehandle_to_list( name,
				      fd 
				    ) == 0
      )
    {
	unicode_add_filehandle_to_list( name,
					fd
				      );
    }// end of if(ascii_add_filehandle_to_list( ))
}// end of add_filehandle_to_list( )


void delete_filehandle_from_list(int fd)
{
    Pfile_handle_entry_t entry      = fhe_list.head;
    Pfile_handle_entry_t pre_entry  = NULL;
    Pfile_handle_entry_t post_entry = NULL;

    while(entry != NULL)
    {
	post_entry = entry->next;

	if(entry->fd == fd)
	{
	    break;
	}// end of if(entry->fd)

	pre_entry = entry;
	entry     = entry->next;	
    }// end of while{entry}
            
    if(entry != NULL)
    {
	if(pre_entry != NULL)
	{
	    pre_entry->next = post_entry;
	    free(entry->fname);
	    free(entry);
	}// end of if(pre_entry)
    }// end of if(entry)
}// end of delete_filehandle_from_list( )


Pfile_handle_entry_t  fetch_filehandle_entry_by_fd(int fd)
{
    Pfile_handle_entry_t entry = fhe_list.head;    
    while( (entry != NULL) && (entry->fd != fd) )
    {
	entry = entry->next;
    }// end of while{ }

    if(entry == NULL)
    {
	return NULL;
    }// end of if( )

    return entry;
}// end of fetch_foffset_by_fd(int fd)


#ifdef H_DEBUG_TEST
void dbg_filehandle_dump( )
{
    term_printf("--------------------------------------------------------------------\n");
    Pfile_handle_entry_t entry = fhe_list.head;    
    while(entry != NULL)
    {
	term_printf( "filename: %s, fd = %d, fileoffset = %x\n",		     
		     entry->fname,
		     entry->fd,
		     entry->foffset
		   );
	entry = entry->next;
    }// end of while{ }
    term_printf("--------------------------------------------------------------------\n");
}// end of dbg_filehandle_dump( )
#endif
/* ================================================================================================================== */
// For ordinary files






// For file-mapping objects
/* ================================================================================================================== */
static fileMapping_handle_entry_list_t h_fileMapping_list;

void init_fileMapping_list( )
{
    h_fileMapping_list.head  = NULL;
    h_fileMapping_list.end   = NULL;
    h_fileMapping_list.count = 0;
}// end of init_fileMapping_list( )


void delete_fileMapping_list( )
{
    PfileMapping_handle_entry_t h_pre_entry = NULL;
    PfileMapping_handle_entry_t h_entry     = h_fileMapping_list.head;

    while(h_entry != NULL)
    {
	if(h_pre_entry != NULL)
	{
	    free(h_pre_entry->fmap_name);
	    free(h_pre_entry);
	}// end of if(h_pre_entry)

	h_pre_entry = h_entry;
	h_entry     = h_entry->next;
    }// end of while{h_entry}

    if(h_pre_entry != NULL)
    {
	free(h_pre_entry->fmap_name);
	free(h_pre_entry);
    }// end of if(h_pre_entry)

}// end of delete_fileMapping_list( )


void add_fileMappinghandle_to_list( uint32_t		  name,   // file-mapping object's name
				    int	     		  fmap_d, // file-mapping object's handle
				    file_handle_entry_t * file_entry,
				    int     		  size,   // size of the file-mapping object
				    int	    		  a_or_w  // 0 --- ascii; 1 --- unicode
				  )
{
    int  i   = 0;
    unsigned short tmp = 0;
    char tmp_bytes[256];
    PfileMapping_handle_entry_t h_entry = (PfileMapping_handle_entry_t)
					  malloc(sizeof(fileMapping_handle_entry_t));
    h_entry->fmap_name  = NULL;
    //h_entry->file_d    = file_d;
    h_entry->file_entry = file_entry;
    h_entry->fmap_d     = fmap_d;
    h_entry->size       = size;
    h_entry->next       = NULL;

    if(a_or_w == 0)
    {
	// ascii
	do
	{
	    TEMU_read_mem( name,
			   1,
			   ( (char *)(&tmp) )
			 );
	    if(tmp == (char)'\0')
	    {
		break;
	    }// end of if(tmp)
	
	    tmp_bytes[i] = tmp;
	    i = i + 1;
	}while(tmp != (char)'\0');
	tmp_bytes[i] = '\0';	
    }
    else
    {
	// unicode
	do
	{
	    TEMU_read_mem( name,
			   2,
			   ( (char *)(&tmp) )
			 );
	    if(tmp == (unsigned short)0)
	    {
		break;
	    }// end of if(tmp)
	
	    tmp_bytes[i] = *((char *)(&tmp));
	    i = i + 1;
	}while(tmp != (unsigned short)0);
	tmp_bytes[i] = '\0';	
    }// end of if(a_or_w)

    h_entry->fmap_name = (char *)malloc(sizeof(char) * (i + 1));
    strcpy( tmp_bytes,
	    h_entry->fmap_name
	  );
    h_entry->fmap_name[i] = '\0';

    if(h_fileMapping_list.head == NULL)
    {
	h_fileMapping_list.head = h_entry;
	h_fileMapping_list.end  = h_entry;
    }
    else
    {
	(h_fileMapping_list.end)->next = h_entry;
	h_fileMapping_list.end	       = h_entry;
    }// end of if(h_fileMapping_list.head)

    h_fileMapping_list.count = h_fileMapping_list.count + 1;
}// end of add_fileMappinghandle_to_list( )


PfileMapping_handle_entry_list_t fetch_fileMappinghandle_entry_by_handle(int fmap_handle)
{
    PfileMapping_handle_entry_t h_entry = h_fileMapping_list.head;
    while(h_entry != NULL)
    {
	if(h_entry->fmap_d == fmap_handle)
	{
	    return h_entry;
	}// end of if(h_entry->fmap_d)

	h_entry = h_entry->next;
    }// end of while{h_entry}

    return NULL;
}// end of fetch_fileMappinghandle_entry_by_handle( )

PfileMapping_handle_entry_list_t fetch_fileMappinghandle_entry_by_name( uint32_t name,
									int	 a_or_w // 0 --- ascii, 1 --- unicode;
								      )
{ 
    int  i = 0;
    unsigned short tmp = 0;
    char databuf[256];
    PfileMapping_handle_entry_t h_entry = NULL;

    // get file-name
    /* --------------------------------------------------------------- */
    if(a_or_w == 0)
    {
	do
	{
	    TEMU_read_mem( name,
			   1,
			   &tmp
			 );
	    if(tmp == (char)0)
	    {
		break;
	    }// end of if(tmp)

	    databuf[i] = tmp;
	    i = i + 1;
	}while(*( (char *)(&tmp) ) != (char)0);
    }
    else
    {
	do
	{
	    TEMU_read_mem( name,
			   2,
			   &tmp
			 );
	    if(tmp == (unsigned short)0)
	    {
		break;
	    }// end of if(tmp)

	    databuf[i] = *((char *)(&tmp));
	    i = i + 1;
	}while(*( (char *)(&tmp) ) != (char)0);	
    }// end of if(a_or_w)

    databuf[i] = '\0';
    /* --------------------------------------------------------------- */
    // get file-name

    h_entry = h_fileMapping_list.head;
    while(h_entry != NULL)
    {
	if( strcmp( h_entry->fmap_name,
		    databuf
		  ) == 0
	  )
	{
	    return h_entry;
	}// end of if( )

	h_entry = h_entry->next;
    }// end of while{h_entry}
    return NULL;
}// end of fetch_fileMappinghandle_entry_by_name( )
/* ================================================================================================================== */
// For file-mapping objects
