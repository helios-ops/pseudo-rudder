%{
#include <stdio.h>
#include <string.h>
#include "function_summary_yacc.tab.h"
%}

NUM  [0-9]
WS   [ \t]
NAME [A-Za-z@0-9_]

%%
func         return FUNC_START;
vaddr        return VADDR;
=	     return EQ;
;	     return SEMICOLON;
argsize      return ARGSIZE;
:	     return TOKENIZER;

{NUM}+       yylval = strdup(yytext); return NUMBER;
\n	  
{WS}+

{NAME}+      yylval = strdup(yytext); return NAME_STR;   
%%
