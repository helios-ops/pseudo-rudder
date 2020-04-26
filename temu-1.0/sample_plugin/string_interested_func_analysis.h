#ifndef H_STRING_INTERESTED_FUNC_ANALYSIS_H
    #define H_STRING_INTERESTED_FUNC_ANALYSIS_H
    
    #include <inttypes.h>
    
    int _strcpy_hook_ret(void * opaque);
    int _strcpy_hook_call(void * opaque);
    
    int _strlen_hook_ret(void * opaque);
    int _strlen_hook_call(void * opaque);

    
#endif
