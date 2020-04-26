#ifndef H_JCC_PRED_BRANCH_H

    #define H_JCC_PRED_BRANCH_H


    void concrete_jcc_branch_analyze( uint8_t  * insn_bytes,
				      uint32_t   insn_addr,
				      int        insn_len,
			              int      * predicate,
				      uint32_t * tbranch,
				      uint16_t * pred_bits
		  	            );

#endif
