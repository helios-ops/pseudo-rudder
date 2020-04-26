#include "TEMU_main.h"
#include "../sample_plugin/H_test_config.h"

void OPPROTO glue(op_opt_movl_A0,REGNAME)(void)
{
    A0 = (uint32_t)REG; 

    // HHui added at June 29th, 2011 FOR symbolic address resolving !
    /* ----------------------------------------------------------------------- */    
    if( (temu_plugin != NULL) && 
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_symbolic_addressing_check != NULL)
      )
    {
	temu_plugin->HHui_symbolic_addressing_check(NB_REG);
    }// end of if( )    
    /* ----------------------------------------------------------------------- */
}

void OPPROTO glue(op_opt_addl_A0,REGNAME)(void)
{
    A0 = (uint32_t)(A0 + REG);

    // HHui added at June 29th, 2011 FOR symbolic address resolving !
    /* ----------------------------------------------------------------------- */
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_symbolic_addressing_check != NULL)
      )
    {
	temu_plugin->HHui_symbolic_addressing_check(NB_REG);
    }// end of if( )    
    /* ----------------------------------------------------------------------- */
}

void OPPROTO glue(glue(op_opt_addl_A0,REGNAME),_s1)(void)
{
    A0 = (uint32_t)(A0 + (REG << 1));

    // HHui added at June 29th, 2011 FOR symbolic address resolving !
    /* ----------------------------------------------------------------------- */
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_symbolic_addressing_check != NULL)
      )
    {
	temu_plugin->HHui_symbolic_addressing_check(NB_REG);
    }// end of if( )    
    /* ----------------------------------------------------------------------- */
}

void OPPROTO glue(glue(op_opt_addl_A0,REGNAME),_s2)(void)
{
    A0 = (uint32_t)(A0 + (REG << 2));

    // HHui added at June 29th, 2011 FOR symbolic address resolving !
    /* ----------------------------------------------------------------------- */
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_symbolic_addressing_check != NULL)
      )
    {
	temu_plugin->HHui_symbolic_addressing_check(NB_REG);
    }// end of if( )    
    /* ----------------------------------------------------------------------- */

}

void OPPROTO glue(glue(op_opt_addl_A0,REGNAME),_s3)(void)
{
    // HHui added at June 29th, 2011 FOR symbolic address resolving !
    /* ----------------------------------------------------------------------- */
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_symbolic_addressing_check != NULL)
      )
    {
	temu_plugin->HHui_symbolic_addressing_check(NB_REG);
    }// end of if( )    
    /* ----------------------------------------------------------------------- */

    A0 = (uint32_t)(A0 + (REG << 3));
}

void OPPROTO glue(op_opt_movl_T0,REGNAME)(void)
{
    T0 = REG;
}

void OPPROTO glue(op_opt_movl_T1,REGNAME)(void)
{
    T1 = REG;
}

void OPPROTO glue(op_opt_movh_T0,REGNAME)(void)
{
    T0 = REG >> 8;
}

void OPPROTO glue(op_opt_movh_T1,REGNAME)(void)
{
    T1 = REG >> 8;
}

void OPPROTO glue(glue(op_opt_movl,REGNAME),_T0)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_write_register_access != NULL)
      )
    {
	
	temu_plugin->HHui_write_register_access( NB_REG,
					 	 0,
				      	         4
				   	       );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (uint32_t)T0;
}

void OPPROTO glue(glue(op_opt_movl,REGNAME),_T1)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_write_register_access != NULL)
      )
    {
	
	temu_plugin->HHui_write_register_access( NB_REG,
					 	 0,
				      	         4
				   	       );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (uint32_t)T1;
}

void OPPROTO glue(glue(op_opt_movl,REGNAME),_A0)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	(temu_plugin->HHui_write_register_access != NULL)
      )
    {
	
	temu_plugin->HHui_write_register_access( NB_REG,
					 	 0,
				      	         4
				   	       );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (uint32_t)A0;
}


/* mov T1 to REG if T0 is true */
void OPPROTO glue(glue(op_opt_cmovw,REGNAME),_T1_T0)(void)
{
    if (T0)
    {
        // HHui added callback
        /* ------------------------------------------------------------------------------------ */
    #if TAINT_ENABLED
        if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
            (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	    (temu_plugin->HHui_write_register_access != NULL)
          )
        {
 	
	    temu_plugin->HHui_write_register_access( NB_REG,
					 	     0,
				      	             2
				   	           );
        }// end of if( )
    #endif
        /* ------------------------------------------------------------------------------------ */

        REG = (REG & ~0xffff) | (T1 & 0xffff);

    }// end of if( )
    FORCE_RET();
}

void OPPROTO glue(glue(op_opt_cmovl,REGNAME),_T1_T0)(void)
{
    if (T0)
    {
        // HHui added callback
        /* ------------------------------------------------------------------------------------ */
    #if TAINT_ENABLED
        if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
            (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
	    (temu_plugin->HHui_write_register_access != NULL)
          )
        {
 	
	    temu_plugin->HHui_write_register_access( NB_REG,
					 	     0,
				      	             4
				   	           );
        }// end of if( )
    #endif
        /* ------------------------------------------------------------------------------------ */

        REG = (uint32_t)T1;
    }// end of if( )
    FORCE_RET();
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movw,REGNAME),_T0)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      0,
			      	              2
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */


    REG = (REG & ~0xffff) | (T0 & 0xffff);
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movw,REGNAME),_T1)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      0,
			      	              2
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */


    REG = (REG & ~0xffff) | (T1 & 0xffff);
}

/* NOTE: A0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movw,REGNAME),_A0)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      0,
			      	              2
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */


    REG = (REG & ~0xffff) | (A0 & 0xffff);
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movb,REGNAME),_T0)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      0,
			      	              1
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (REG & ~0xff) | (T0 & 0xff);
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movh,REGNAME),_T0)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      1,
			      	              1
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (REG & ~0xff00) | ((T0 & 0xff) << 8);
}

/* NOTE: T1 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movb,REGNAME),_T1)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      0,
			      	              1
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (REG & ~0xff) | (T1 & 0xff);
}

/* NOTE: T1 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movh,REGNAME),_T1)(void)
{
    // HHui added callback
    /* ------------------------------------------------------------------------------------ */
#if TAINT_ENABLED
    if( (temu_plugin != NULL) &&
// no taint has ever been introduced !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
        (temu_plugin->symexe_enabled_for_taint != 0) &&  	
#endif
        (temu_plugin->HHui_write_register_access != NULL)
      )
    {
 	
     temu_plugin->HHui_write_register_access( NB_REG,
				 	      1,
			      	              1
			   	            );
    }// end of if( )
#endif
    /* ------------------------------------------------------------------------------------ */

    REG = (REG & ~0xff00) | ((T1 & 0xff) << 8);
}

