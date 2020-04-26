%{
#include <stdio.h>
#include <string.h>
#include "combine_protocol_analysis_yacc.tab.h"
%}

NUM  [0-9]
WS   [ \t]


%%
LengthDomain return LEN_DOMAIN;
:	     return TOKENIZER;
ByteCount    return BYTE_COUNT;
-	     return SEPARATOR;
;	     return SEMICOLON;
{NUM}+       yylval = strdup(yytext); return NUMBER;
\n	  
{WS}+
%%
