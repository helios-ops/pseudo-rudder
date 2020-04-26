/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/**********************************************************************
 * hookapi.c
 * @Author Heng Yin <hyin@ece.cmu.edu>
 * This file is responsible for registering and calling function hooks.
 * 
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include <string.h>
#include <limits.h>
#include <sys/queue.h>
#include "config.h"
#include "hookapi.h"
#include "hooks/function_map.h"
#include "TEMU_lib.h"

#include "../sample_plugin/H_test_config.h"

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    #include "../sample_plugin/function_summary.h"
#endif

typedef struct hookapi_record
{
  uint32_t eip;
  int is_global;
  uint32_t esp; //for hooking function return
  uint32_t cr3; //for hooking function return
  hook_proc_t fnhook;
  void *opaque;
  uint32_t sizeof_opaque;
  LIST_ENTRY(hookapi_record) link;
} hookapi_record_t;

typedef struct hookapi_handle{
  uintptr_t handle;
  LIST_ENTRY(hookapi_handle) link;
} hookapi_handle_t;


#define HOOKAPI_HTAB_SIZE 256
LIST_HEAD(hookapi_record_list_head, hookapi_record) 
	hookapi_record_heads[HOOKAPI_HTAB_SIZE];

LIST_HEAD(hookapi_handle_list_head, hookapi_handle) hookapi_handle_head = 
	LIST_HEAD_INITIALIZER(&hookapi_handle_head);

static inline void hookapi_insert(hookapi_record_t *record)
{
  struct hookapi_record_list_head *head =
      &hookapi_record_heads[record->eip & (HOOKAPI_HTAB_SIZE - 1)];
  
  LIST_INSERT_HEAD(head, record, link); 
  
  hookapi_handle_t *handle_info = malloc(sizeof(hookapi_handle_t));
  if(handle_info) {
    handle_info->handle = (uintptr_t)record;
    LIST_INSERT_HEAD(&hookapi_handle_head, handle_info, link);
  }
}

static void hookapi_remove_all( )
{
  hookapi_record_t *hrec;
  int i;

  for(i = 0; i<HOOKAPI_HTAB_SIZE; i++) 
  {
      struct hookapi_record_list_head * head = &hookapi_record_heads[i];
      while(!LIST_EMPTY(head)) 
      {   
	  hrec = LIST_FIRST(head);
	  LIST_REMOVE(hrec, link);
	  if(hrec->opaque != 0 && (uintptr_t)(hrec->opaque) != 1) 
	  {
	      // term_printf("hookapi_remove_all() : free(hrec->opaque)  \n");

              free(hrec->opaque);
	      hrec->opaque = NULL;

	  }// end of if( )

	  // term_printf("hookapi_remove_all() : free(hrec)  \n");
	  free(hrec);
      }// end of while{ }
  }// end of for{ }
  
  term_printf(" Removing hookapi_record_heads finished !");

  hookapi_handle_t *handle_info;
  while(!LIST_EMPTY(&hookapi_handle_head)) 
  {
    handle_info = LIST_FIRST(&hookapi_handle_head);
    LIST_REMOVE(handle_info, link);
    free(handle_info);
  }// end of while{ }
    
}

static void hookapi_save(QEMUFile *f, void *opaque)
{
  hookapi_record_t *hrec;
  int i;
  Dl_info info;
  uint32_t len;
  
  for(i = 0; i < HOOKAPI_HTAB_SIZE; i++) 
  {
    LIST_FOREACH(hrec, &hookapi_record_heads[i], link) 
    {
      qemu_put_be32(f, hrec->eip);
      
      if(dladdr((void *)hrec->fnhook, &info) == 0) {
        fprintf(stderr, "%s\n", dlerror());
        return;
      }

/*     int general_function_summary_begin(void * opaque);
       int general_function_summary_end(void * opaque);
 */
/*
    if( (uint32_t)(hrec->fnhook) == (uint32_t)(general_function_summary_begin) )
    {
    }
    else
    {
*/
      len = strlen(info.dli_fname) + 1;
      qemu_put_be32(f, len);
      qemu_put_buffer(f, (uint8_t*)info.dli_fname, len); //module name
      qemu_put_be32(f, (uint32_t)((uintptr_t)hrec->fnhook - (uintptr_t)info.dli_fbase)); //relative address
      qemu_put_be32(f, (uint32_t)hrec->is_global);
      qemu_put_be32(f, hrec->esp);
      qemu_put_be32(f, hrec->cr3);
      qemu_put_be32(f, (uint32_t)(uintptr_t)hrec->opaque); //hacky!!!
      qemu_put_be32(f, hrec->sizeof_opaque);
      if(hrec->sizeof_opaque)
        qemu_put_buffer(f, (uint8_t *)hrec->opaque, hrec->sizeof_opaque);
      qemu_put_byte(f, 0xff); //separator
    }
  }
  qemu_put_be32(f, 0); //terminator
}

static int hookapi_load(QEMUFile *f, void *opaque, int version_id)
{  
  hookapi_remove_all();
  
  uint32_t eip, len;
  uintptr_t base = 0, relative_addr;
  hookapi_record_t *record;
  
  char mod_name[PATH_MAX];
  void *handle;
  
  while((eip = qemu_get_be32(f))) {
    len = qemu_get_be32(f);
    if(len < 1 || len > PATH_MAX) return -EINVAL;
    
    qemu_get_buffer(f, (uint8_t *)mod_name, len);
    handle = dlopen(mod_name, RTLD_NOLOAD);
    if(NULL == handle) {
      fprintf(stderr, "%s is not loaded \n", mod_name);
      dlclose(handle);
      return -EINVAL;
    }
    void *sym;
    if ((sym = dlsym(handle, "_init"))) {
      Dl_info dli;
      if (dladdr(sym, &dli)) 
        base = (uintptr_t) dli.dli_fbase;
    } else {
      fprintf(stderr, "cannot find base address of %s\n", mod_name);
      dlclose(handle);
      return -EINVAL;
    }
   
	relative_addr = qemu_get_be32(f);

    record = malloc(sizeof(hookapi_record_t));
    if(record == NULL) {
      fprintf(stderr, "out of memory!\n");
      dlclose(handle);
      return -EINVAL;
    }    

    record->fnhook = (hook_proc_t)(relative_addr + base);
    record->is_global = (int)qemu_get_be32(f);
    record->esp = qemu_get_be32(f);
    record->cr3 = qemu_get_be32(f);
    record->opaque = (void *)(uintptr_t)qemu_get_be32(f);
    record->sizeof_opaque = qemu_get_be32(f);
    if(record->sizeof_opaque) {
      if(NULL == (record->opaque = malloc(record->sizeof_opaque))) {
        fprintf(stderr, "out of memory: size=%d\n", record->sizeof_opaque);
        dlclose(handle);
        free(record);
        return -EINVAL;
      }
      qemu_get_buffer(f, (uint8_t *)record->opaque, record->sizeof_opaque);
    }      
    uint8_t separator = qemu_get_byte(f);
    if(separator != 0xff) {
      dlclose(handle);
      free(record);
      return -EINVAL; 
    } 

    hookapi_insert(record);
    dlclose(handle);
  }

  return 0;
}

void init_hookapi()
{
  int i;
  for (i = 0; i < HOOKAPI_HTAB_SIZE; i++)
    LIST_INIT(&hookapi_record_heads[i]);


#ifndef HHUI_FUNC_SUMMARY_ENABLED
  register_savevm("hookapi", 0, 2, hookapi_save, hookapi_load, NULL);
#endif
}


void hookapi_cleanup()
{
  hookapi_remove_all();  
  
  // HHui deleted !
  deregister_savevm("hookapi", 0);
}

#if 0
int register_hookapi(uint32_t eip, hook_proc_t fnhook, void *opaque, uint32_t sizeof_opaque)
{
  struct list_head *pos, *head =
      &hookapi_htab[eip & (HOOKAPI_HTAB_SIZE - 1)];
  hookapi_record_t *hrec;

  list_for_each(pos, head) {
    hrec = list_entry(pos, hookapi_record_t, link);
    if (hrec->eip == eip) {
      hrec->fnhook = fnhook;
      hrec->opaque = opaque;
      hrec->sizeof_opaque = opaque? sizeof_opaque: 0;
      return 0;
    }
  }

  hrec = malloc(sizeof(hookapi_record_t));
  if (hrec == NULL)
    return -1;

  hrec->eip = eip;
  hrec->fnhook = fnhook;
  hrec->opaque = opaque;
  hrec->sizeof_opaque = opaque? sizeof_opaque: 0;
  list_add(&hrec->link, head);
  return 0;
}
#endif

uintptr_t hookapi_hook_function(
               int is_global,
               uint32_t eip, 
               hook_proc_t fnhook, 
               void *opaque, 
               uint32_t sizeof_opaque
               )
{
  /*
  term_printf( "hookapi_record_t size is %d\n",
	       sizeof(hookapi_record_t)
	     );
   */

  hookapi_record_t *record = malloc(sizeof(hookapi_record_t));
  if (record == NULL)
  {
    return 0;
  }// end of if( )

  bzero(record, sizeof(hookapi_record_t));
  record->eip = eip;
  record->is_global = is_global;
  record->fnhook = fnhook;
  record->sizeof_opaque = sizeof_opaque;
  record->opaque = opaque;
  
  hookapi_insert(record);
  return (uintptr_t)record;
}


int HH_find_hook( uint32_t    eip,
		  uint32_t    esp,
		  hook_proc_t fnhook		  
		)
{
    struct hookapi_record_list_head * record_list  = &( hookapi_record_heads[eip & (HOOKAPI_HTAB_SIZE - 1)] );
    hookapi_record_t * record_entry = record_list->lh_first;
    
    while(record_entry != NULL)
    {
	if( ( (eip == record_entry->eip) &&
	      (esp == record_entry->esp)
	    ) &&
	    (fnhook == record_entry->fnhook)
	  )
	{
	    return 1;
	}// end of if( )

	record_entry = (record_entry->link).le_next;
    }// end of while{record_entry}

    return 0;
}// end of HH_find_hook( )

uintptr_t 
HH_hookapi_hook_return(
       		        uint32_t    eip, 
			uint32_t    esp, 
               		hook_proc_t fnhook, 
       		        void   *    opaque,
               		uint32_t    sizeof_opaque
               	      )
{
  hookapi_record_t *record = NULL;

  if( HH_find_hook( eip,
		    esp,
		    fnhook
	          ) != 0
    )
  {
      return 0;
  }// end of if(HH_find_hook)

  record = malloc(sizeof(hookapi_record_t));
  if (record == NULL)
    return 0;

  record->eip           = eip;
  record->is_global     = 0;
  record->esp           = esp;
  record->cr3           = TEMU_cpu_cr[3];
  record->fnhook        = fnhook;
  record->sizeof_opaque = sizeof_opaque;
  record->opaque        = opaque;

  hookapi_insert(record);
  return (uintptr_t)record;
}


uintptr_t 
hookapi_hook_return(
               uint32_t eip, 
               hook_proc_t fnhook, 
               void *opaque, 
               uint32_t sizeof_opaque
               )
{
  hookapi_record_t *record = malloc(sizeof(hookapi_record_t));
  if (record == NULL)
    return 0;

  record->eip = eip;
  record->is_global = 0;
  record->esp = TEMU_cpu_regs[R_ESP];
  record->cr3 = TEMU_cpu_cr[3];
  record->fnhook = fnhook;
  record->sizeof_opaque = sizeof_opaque;
  record->opaque = opaque;

  hookapi_insert(record);
  return (uintptr_t)record;
}


void hookapi_remove_hook(uintptr_t handle)
{
  //we need to sanitize this handle. 
  //check if this handle exists in our handle list


  hookapi_handle_t *handle_info;

  LIST_FOREACH(handle_info, &hookapi_handle_head, link) 
  {
    if(handle_info->handle != handle)
      continue;

    //we found this handle
    LIST_REMOVE(handle_info, link);
    free(handle_info);    
    hookapi_record_t *record = (hookapi_record_t *)handle;
    LIST_REMOVE(record, link);
    //here, we do not free record->opaque, because caller should free it
    free(record);
    return;
  }
  assert(0); //this handle is invalid
}

#if 0
int remove_hookapi(uint32_t eip)
{
  struct list_head *pos, *head =
      &hookapi_htab[eip & (HOOKAPI_HTAB_SIZE - 1)];
  hookapi_record_t *hrec;

  /* here we don't free opaque. caller should take care of it*/
  list_for_each(pos, head) {
    hrec = list_entry(pos, hookapi_record_t, link);
    if (hrec->eip == eip) {
      list_del(pos);
      free(hrec);
      break;
    }
  }
  return 0;
}
#endif

void hookapi_check_call(int in_context)
{
#ifdef H_DEBUG_TEST
  uint32_t hasCalled = 0;  
  uint32_t last_func = 0;
  uint32_t last_eip  = 0;
#endif

  uint32_t eip = *TEMU_cpu_eip;
  struct hookapi_record_list_head *head =
      &hookapi_record_heads[eip & (HOOKAPI_HTAB_SIZE - 1)];
  hookapi_record_t *record, *tmp;

  //NOTE: this is a safe version of LIST_FOREACH
  for(record = head->lh_first; record;  record = tmp) { 
	tmp = record->link.le_next;
/*
  record = head->lh_first;
  while(record != NULL)
  { 
      tmp = record->link.le_next;
*/
      if(record->eip != eip) 
      {
          continue;
      }

      if( record->is_global || 
          (in_context && record->esp==0) || // in monitored context
          ( record->cr3 == TEMU_cpu_cr[3] && 
            TEMU_cpu_regs[R_ESP] - record->esp < 80
	  ) //function return
        ) 
      {
          record->fnhook(record->opaque); 
      #ifdef H_DEBUG_TEST
          if(hasCalled == 1)
          {
              if( (last_func == (uint32_t)(record->fnhook)) && 
		  (record->eip == last_eip)
		)
	      {
	          term_printf( "hook-func[%x] has already been called at this point [%x]!\n",			   
			       last_func,
			       record->eip
			     );
	      }// end of if(last_func)	  
          }// end of if(hasCalled)
          last_func = (uint32_t)(record->fnhook);
	  last_eip  = record->eip;
          hasCalled = 1;
      #endif
      }// end of if(record->is_global)      

      // record = tmp;
  }// end of while{record}
}

void hookapi_hook_function_byname(const char *mod_name, const char *fun_name,
                    int is_global, hook_proc_t fnhook, void *opaque, uint32_t sizeof_opaque)
{
  uint32_t eip = query_eip(mod_name, fun_name);
  if (eip == 0) {
    /* <module,function> pair unknown. Add to map containing functions to 
       hook when they are loaded by OS */
    add_fun_to_hook(mod_name, fun_name, (uintptr_t)fnhook, is_global);
    printf("Deferring hooking of %s::%s\n", mod_name, fun_name);
  }
  else {
    printf("Hooking %s::%s @ 0x%x\n", mod_name, fun_name, eip);
    hookapi_hook_function(is_global, eip, fnhook, opaque, sizeof_opaque);
  }
}
