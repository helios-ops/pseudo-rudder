#ifndef H_STP_VARIABLES_H

    #define H_STP_VARIABLES_H

    typedef struct stp_variable_entry
    {
	HExpr 			    v_expr;
	struct stp_variable_entry * next;

    }stp_variable_entry_t, *Pstp_variable_entry_t;


    typedef struct stp_variable_list
    {
	struct stp_variable_entry * head;
	struct stp_variable_entry * end;

	int  count;
    }stp_variable_list_t, *Pstp_variable_list_t;



    typedef HExpr * (*OBTAIN_STP_VARS_ARRAY)(int * count);

    /* ------------------------------------------------------------------------------- */
    void init_stp_vlist( );

    void add_stp_vlist_entry(HExpr v_expr);

    void delete_stp_vlist( );

    HExpr * obtaint_stp_vars_array(int * count);
    /* ------------------------------------------------------------------------------- */


#endif
