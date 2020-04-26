#ifndef H_FILEHANDLE_H
    #define H_FILEHANDLE_H

    #include <inttypes.h>

// ordinary file's Open( ) and Read( )
    typedef struct file_handle_entry
    {
	int      fd;
	uint32_t foffset; // file offset
	char *   fname;
  	struct file_handle_entry * next;
    }file_handle_entry_t, *Pfile_handle_entry_t;

    typedef struct file_handle_entry_list
    {
	struct file_handle_entry * head;
	struct file_handle_entry * end;

	int count;
    }file_handle_entry_list_t, *Pfile_handle_entry_list_t;


// file-mapping mechanism
    typedef struct fileMapping_handle_entry
    {
	// int      file_d;    // descriptor of the target file 
	file_handle_entry_t * file_entry;
        int      fmap_d;    // descriptor of the file-mapping object
        char *   fmap_name;
        uint32_t foffset;
	uint32_t size;      // map-size specified by CreateFileMapping( )

	struct fileMapping_handle_entry * next;
    }fileMapping_handle_entry_t, *PfileMapping_handle_entry_t;


    typedef struct fileMapping_handle_entry_list
    {
	struct fileMapping_handle_entry * head;
	struct fileMapping_handle_entry * end;

	int count;
    }fileMapping_handle_entry_list_t, *PfileMapping_handle_entry_list_t;


    // ordinary file's Open( ) and Read( )    
    /* ------------------------------------------------------------------------------------- */
    void init_filehandle_entry_list( );
    void delete_filehandle_entry_list( );

    // util for Readfile( )
    Pfile_handle_entry_t  fetch_filehandle_entry_by_fd(int fd);

    // util for OpenFile( )
    int ascii_add_filehandle_to_list( uint32_t name, 
				      int      fd
			            );
    int unicode_add_filehandle_to_list( uint32_t name,
					int      fd
				      );

    void add_filehandle_to_list( uint32_t name,
				 int      fd
			       );

    // util for CloseFile( )
    void delete_filehandle_from_list(int fd);
    /* ------------------------------------------------------------------------------------- */    


    // file-mapping mechanisms' Open( ) and Read( )
    /* ------------------------------------------------------------------------------------- */    
    void init_fileMapping_list( );
    void delete_fileMapping_list( );

    void add_fileMappinghandle_to_list( uint32_t 	      name,
					int	 	      fmap_d,
				        file_handle_entry_t * file_entry,
					int      	      size,
					int		      a_or_w
				      );
    PfileMapping_handle_entry_list_t fetch_fileMappinghandle_entry_by_name( uint32_t name,
									    int	     a_or_w
									  );

    PfileMapping_handle_entry_list_t fetch_fileMappinghandle_entry_by_handle(int fd);
    /* ------------------------------------------------------------------------------------- */    
#endif
