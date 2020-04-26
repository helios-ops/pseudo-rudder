#ifndef H_WINXPSP2_DEFS_H

    #define H_WINXPSP2_DEFS_H

    #define THREAD_LIST_HEAD_IN_EPROCESS 0x190

    #define THREAD_LIST_ENTRY_IN_ETHREAD 0x22c
    
    #define EPROCESS_IN_ETHREAD		 0x220

    #define TEB_IN_KTHREAD		 0x20

    /*
    // Kernel stack !
    uint32_t stackbase_in_kthread = 0;
    #define STACKBASE_IN_KTHREAD 	 0x168
    */

    #define STACKBASE_IN_NT_TIB		 0x4
    #define STACKLIMIT_IN_NT_TIB	 0x8


    #define TID_IN_ETHREAD 	 	 (0x1ec+0x4)
    // #define TID_IN_TEB		 0x20

#endif
