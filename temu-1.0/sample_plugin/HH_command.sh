#!/bin/sh
rm -f plugin.so
rm -f main.o 
rm -f winxpsp2_vad.o 
rm -f winxpsp2_esp_range.o

rm -f branch_save.o 
rm -f HH_encap_taintcheck.o 
rm -f stp_variables.o 
rm -f jcc_pred_branch.o 
rm -f formula_solve.o 
rm -f branch_update_VM.o 
rm -f HVM_state.o 
rm -f H_mem_map.o 
rm -f H_STP_stub.o 
rm -f eflag_tc_monitor.o 
rm -f module_notify.o 
rm -f proc_notify.o 
rm -f insn_effect_restore.o
rm -f tc_symaddr_mem_restore.o
rm -f filehandle.o

rm -f h_atoi.o
rm -f interested_func_analysis.o
rm -f string_interested_func_analysis.o
rm -f H_taint_record.o

rm -f call_analysis.o
rm -f record_potential_error2file.o

rm -f winxp_threading.o

rm -f H_testcase_generation.o

rm -f dbg_util.o

rm -f thread_context.o

# ----------------------function summary ---------------------------#
if test $1 = "func_summary_enable"; then
  rm -f function_summary_yacc.tab.c
  rm -f function_summary_yacc.tab.h
  rm -f lex.yy.c
  rm -f function_summary_yacc.tab.o
  rm -f lex.yy.o
  rm -f taintcheck_hook.o
  rm -f expr_condition.o

  rm -f func_summ_hook.o
  rm -f func_summ_snapshot.o  
fi
# ----------------------function summary ---------------------------#


gcc -Wall -O4 -g -fPIC -MMD -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o main.o main.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o insn_effect_restore.o insn_effect_restore.c


gcc -Wall -O4 -g -fPIC -MMD -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o H_STP_stub.o H_STP_stub.c



gcc -Wall -O4 -g -fPIC -MMD -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o proc_notify.o proc_notify.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o module_notify.o module_notify.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o H_mem_map.o H_mem_map.c


gcc -Wall -O4 -g -fPIC -MMD -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o Reg_convert.o Reg_convert.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o eflag_tc_monitor.o eflag_tc_monitor.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o stp_variables.o stp_variables.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o branch_update_VM.o branch_update_VM.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o branch_save.o branch_save.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o formula_solve.o formula_solve.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o HVM_state.o HVM_state.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o jcc_pred_branch.o jcc_pred_branch.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o HH_encap_taintcheck.o HH_encap_taintcheck.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o winxpsp2_vad.o winxpsp2_vad.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o tc_symaddr_mem_restore.o tc_symaddr_mem_restore.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o FileHandle.o FileHandle.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o winxpsp2_esp_range.o winxpsp2_esp_range.c

# cared function analysis
# --------------------------------------------------------- #
gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o interested_func_analysis.o interested_func_analysis.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o string_interested_func_analysis.o string_interested_func_analysis.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o memory_interested_func_analysis.o memory_interested_func_analysis.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o h_atoi.o h_atoi.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o H_taint_record.o H_taint_record.c

# --------------------------------------------------------- #

gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o H_malloc_data.o H_malloc_data.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o call_analysis.o call_analysis.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o record_potential_error2file.o record_potential_error2file.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o dbg_util.o dbg_util.c


gcc -Wall -O4 -g -fPIC -MMD -std=c99 -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -D_GNU_SOURCE -c -o thread_context.o thread_context.c


# HHui's make-option
##############################################################################################################
function_summary_file_list=""
protocol_analysis_file_list=""
lex_yacc_lib=""

for opt do
  optarg=`expr "x$opt" : 'x[^=]*=\(.*\)'`
  case "$opt" in
  --func_summary_enable|-f) function_summary_file_list="function_summary_lex.yy.o function_summary_yacc.tab.o expr_condition.o taintcheck_hook.o func_summ_hook.o func_summ_snapshot.o"
 lex_yacc_lib="-lfl -ly"
  ;;
  --protocol_analysis|-p) protocol_analysis_file_list="combine_protocol_analysis_lex.yy.o combine_protocol_analysis_yacc.tab.o"
 lex_yacc_lib="-lfl -ly"
  ;;
  esac  
done
##############################################################################################################



# ----------------------function summary begin ---------------------------#

#if test $1 = "func_summary_enable"; then

#if test -n $function_summary_file_list && test -n $(tr -s ' ' $function_summary_file_list); then

rm -f function_summary_yacc.tab.o
rm -f lex.yy.o

rm -f function_summary_yacc.tab.c
rm -f lex.yy.c

bison -d function_summary_yacc.y
flex function_summary_lex.l

gcc function_summary_yacc.tab.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -g -c -o function_summary_yacc.tab.o

gcc lex.yy.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o lex.yy.o

# renaming the lex-object of function-summary's lexer
cp lex.yy.o function_summary_lex.yy.o
rm -f lex.yy.o
rm -f lex.yy.c

gcc expr_condition.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o expr_condition.o

gcc taintcheck_hook.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o taintcheck_hook.o


gcc func_summ_hook.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o func_summ_hook.o


gcc func_summ_snapshot.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o func_summ_snapshot.o

#fi
# ---------------------- function summary end ---------------------------#



gcc winxp_threading.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o winxp_threading.o


gcc H_testcase_generation.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o H_testcase_generation.o


gcc raw_check_pushpop.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o raw_check_pushpop.o



gcc interested_taint_source.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o interested_taint_source.o



# ---------------------- protocol analysis ---------------------------#
#if test -n $protocol_analysis_file_list && test -n $(tr -s ' ' $protocol_analysis_file_list); then

rm -f combine_protocol_analysis_lex.yy.o
rm -f combine_protocol_analysis_yacc.tab.o

rm -f combine_protocol_analysis_yacc.tab.c
rm -f lex.yy.c

bison -d combine_protocol_analysis_yacc.y
flex combine_protocol_analysis_lex.l

gcc combine_protocol_analysis_yacc.tab.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -g -c -o combine_protocol_analysis_yacc.tab.o

# flex-generated lexical-parser
gcc lex.yy.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o lex.yy.o

# renaming the lex-object of protocol analysis's lexer
cp lex.yy.o combine_protocol_analysis_lex.yy.o
rm -f lex.yy.o
rm -f lex.yy.c

#fi
# ---------------------- protocol analysis ---------------------------#



#if test $1 = "func_summary_enable"; then
#g++ -g -Wl -shared interested_taint_source.o H_testcase_generation.o winxp_threading.o expr_condition.o func_summ_hook.o func_summ_snapshot.o taintcheck_hook.o lex.yy.o function_summary_yacc.tab.o string_interested_func_analysis.o memory_interested_func_analysis.o  record_potential_error2file.o H_malloc_data.o call_analysis.o H_taint_record.o h_atoi.o interested_func_analysis.o main.o winxpsp2_vad.o winxpsp2_esp_range.o branch_save.o HH_encap_taintcheck.o tc_symaddr_mem_restore.o stp_variables.o FileHandle.o jcc_pred_branch.o formula_solve.o branch_update_VM.o HVM_state.o H_mem_map.o H_STP_stub.o eflag_tc_monitor.o module_notify.o proc_notify.o insn_effect_restore.o Reg_convert.o dbg_util.o ../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o ../shared/hooks/function_map.o ../shared/reduce_taint.o raw_check_pushpop.o thread_context.o -o plugin.so  -L. -lstp -lm -L../shared/xed2/xed2-ia32/lib -lxed -lfl -ly

#else
#g++ -g -Wl -shared interested_taint_source.o H_testcase_generation.o winxp_threading.o string_interested_func_analysis.o record_potential_error2file.o H_malloc_data.o call_analysis.o H_taint_record.o h_atoi.o interested_func_analysis.o memory_interested_func_analysis.o main.o winxpsp2_vad.o winxpsp2_esp_range.o branch_save.o HH_encap_taintcheck.o tc_symaddr_mem_restore.o stp_variables.o FileHandle.o jcc_pred_branch.o formula_solve.o branch_update_VM.o HVM_state.o H_mem_map.o H_STP_stub.o eflag_tc_monitor.o module_notify.o proc_notify.o insn_effect_restore.o Reg_convert.o dbg_util.o ../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o ../shared/hooks/function_map.o ../shared/reduce_taint.o raw_check_pushpop.o thread_context.o -o plugin.so  -L. -lstp -lm -L../shared/xed2/xed2-ia32/lib -lxed -lfl -ly
#fi


#gcc stp_util_for_temu.c -I../shared/xed2/xed2-ia32/include -I. -I.. -I../i386-softmmu -I../target-i386 -I../fpu -std=c99 -c -g -o stp_util_for_temu.o

g++ -g -Wl -shared thread_context.o interested_taint_source.o H_testcase_generation.o winxp_threading.o $function_summary_file_list $protocol_analysis_file_list string_interested_func_analysis.o memory_interested_func_analysis.o  record_potential_error2file.o H_malloc_data.o call_analysis.o H_taint_record.o h_atoi.o interested_func_analysis.o main.o winxpsp2_vad.o winxpsp2_esp_range.o branch_save.o HH_encap_taintcheck.o tc_symaddr_mem_restore.o stp_variables.o FileHandle.o jcc_pred_branch.o formula_solve.o branch_update_VM.o HVM_state.o H_mem_map.o H_STP_stub.o eflag_tc_monitor.o module_notify.o proc_notify.o insn_effect_restore.o Reg_convert.o dbg_util.o ../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o ../shared/hooks/function_map.o ../shared/reduce_taint.o raw_check_pushpop.o -o plugin.so  -L. -lstp -lm -L../shared/xed2/xed2-ia32/lib -lxed $lex_yacc_lib

str="g++ -g -Wl -shared thread_context.o interested_taint_source.o H_testcase_generation.o winxp_threading.o "$function_summary_file_list" "$protocol_analysis_file_list" string_interested_func_analysis.o memory_interested_func_analysis.o  record_potential_error2file.o H_malloc_data.o call_analysis.o H_taint_record.o h_atoi.o interested_func_analysis.o main.o winxpsp2_vad.o winxpsp2_esp_range.o branch_save.o HH_encap_taintcheck.o tc_symaddr_mem_restore.o stp_variables.o FileHandle.o jcc_pred_branch.o formula_solve.o branch_update_VM.o HVM_state.o H_mem_map.o H_STP_stub.o eflag_tc_monitor.o module_notify.o proc_notify.o insn_effect_restore.o Reg_convert.o dbg_util.o ../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o ../shared/hooks/function_map.o ../shared/reduce_taint.o raw_check_pushpop.o -o plugin.so  -L. -lstp -lm -L../shared/xed2/xed2-ia32/lib -lxed "$lex_yacc_lib

echo $str


ls -al plugin.so



