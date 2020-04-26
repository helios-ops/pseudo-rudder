#ifndef H_i386_REG_INIT_H

    #define H_i386_REG_INIT_H

    #include <stdlib.h>
    #include <string.h>

    #include "stmt.h"

    /* --------------------------------------------------------------------------- */

    extern vector<VarDecl *>  i386_gen_regs;

    extern vector<VarDecl *>  i386_EFLAGS_bits;

    /* --------------------------------------------------------------------------- */


    void i386_reg_init( );

    VarDecl * Obtain_i386_regvar_byname(string name);

    VarDecl * Obtain_i386_EFLAGS_bit_var_byname(string name);


#endif
