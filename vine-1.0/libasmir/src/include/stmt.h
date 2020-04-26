/*
Vine is Copyright (C) 2006-2009, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU GPL,
version 2 or later, but it is made available WITHOUT ANY WARRANTY.
See the top-level README file for more details.

For more information about Vine and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _STMT_H
#define _STMT_H
#include "irvisitor.h"
#include "exp.h"

#include "branch_save.h"


#ifndef H_term_printf_H
   #define H_term_printf_H
extern void (*H_term_printf)( const char * fstr, ... );
#endif

enum stmt_type_t {JMP,CJMP, SPECIAL, MOVE,  COMMENT,  LABEL, EXPSTMT, VARDECL,
                  CALL, RETURN, FUNCTION, ASSERT};


#ifndef __cplusplus
typedef struct Stmt Stmt;
#endif

#ifdef __cplusplus
#include <stdint.h>
#include <string>
#include <vector>
using namespace std;


class Stmt 
{
 public:
  virtual ~Stmt() { };
  virtual void accept(IRVisitor *v) = 0;
  virtual string tostring() = 0;
  static Stmt *clone(Stmt *s);
  static void destroy(Stmt *s);

  Stmt(stmt_type_t st, address_t asm_ad, address_t ir_ad)
    { asm_address = asm_ad; ir_address = ir_ad; stmt_type = st; };
  
  /// Make a deep copy of the stmt
  virtual Stmt *clone() const = 0;

  /// The assembly instruction address for this statement.
  /// Many statements may have the same asm_address since a single
  /// assembly instruction may translate into many IR statements
  address_t asm_address;
  /// The unique ir instruction address for this statement.
  /// The uniqueness if determined by the application using this
  /// object, e.g., translation keeps a counter.
  address_t ir_address;
  stmt_type_t stmt_type;

  virtual int symexe( HVC   hvc, 
		      HExpr path_expr
		    ) = 0 ;
};

class VarDecl : public Stmt 
{
 public:
  VarDecl(string name, reg_t typ, address_t asm_ad = 0x0, 
	  address_t ir_ad = 0x0);
  VarDecl(Temp *t);
  VarDecl(const VarDecl &other);
  virtual ~VarDecl() { };
  virtual void accept(IRVisitor *v) { v->visitVarDecl(this); };
  virtual string tostring();
  virtual VarDecl *clone() const;

  string name;
  reg_t typ;
  
  
  /* --------------------------------------------------------------------------- */
  void concrete_read( char * buf, int size );

  void symbolic_write( HVC hvc, HExpr expr );


  /* Both for general registers;
     For EFLAGS only reg_idx would be possible as EFLAG bit index;
     Nonsense for temp variables;
   */
  int  reg_idx;
  int  reg_offset;
  int  reg_size;
  
  /*
      0 --- general reg
      1 --- EFLAG bit
      2 --- temp variable
   */ 
  int  var_type;
  
  
  VarDecl( string myname,
	   int    myvar_type, 
	   reg_t  mytype,	   
	   int	  myreg_idx,
	   int 	  myreg_offset,
	   int	  myreg_size
	 );


  H_R_value H_value;

  virtual int symexe( HVC   hvc, 
		      HExpr path_expr
		    )
  {
      return 0;
  }// end of symexe(HVC hvc)
  /* --------------------------------------------------------------------------- */

};

class Move : public Stmt 
{
 public:
  Move(Exp *l, Exp *r, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Move(const Move &other);
  virtual ~Move() { };
  virtual void accept(IRVisitor *v) { v->visitMove(this); };
  virtual string tostring();
  virtual Move *clone() const;

  Exp *lhs;
  Exp *rhs;
  
  virtual int symexe( HVC   hvc, 
		      HExpr path_expr
		    );
};


class Label : public Stmt {
 public:
  Label(string l, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Label(const Label &other);
  virtual ~Label() { };
  virtual void accept(IRVisitor *v) { v->visitLabel(this); };
  virtual string tostring();
  virtual Label *clone() const;
  string label;

  void pre_parse( int	   * label_type,
	          uint32_t * label_id		    
		);

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};


class Jmp : public Stmt {
 public:
  Jmp( Exp *e, address_t asm_ad = 0x0, address_t ir_ad = 0x0 );
  Jmp(const Jmp &other);
  virtual ~Jmp() { };
  virtual void accept(IRVisitor *v) { v->visitJmp(this); };
  virtual string tostring();
  virtual Jmp *clone() const;
  Exp *target;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};


class CJmp : public Stmt {
 public:
  CJmp(Exp *c, Exp *t, Exp *f, address_t asm_ad = 0x0, 
       address_t ir_ad = 0x0);
  CJmp(const CJmp &other);
  virtual ~CJmp() { };

  virtual void accept(IRVisitor *v) { v->visitCJmp(this); }
  virtual string tostring();
  virtual CJmp *clone() const;
  Exp *cond;
  Exp * t_target;    // true edge target
  Exp * f_target;    // false edge target


  uint32_t symexe_pathvc( HVC	      hvc, 
		          HExpr *     global_path_expr,
		    	  HExpr *     local_pred_expr, 
		      
		    	  int	      H_predicate,
		   	  uint32_t    tbranch,
		   	  uint32_t    fbranch,
		  	  BRANCH_SAVE mybranch_save,

			  int   *     label_type,

			  int	      isREP  // denote whether this CJMP belong to a REP-insn or not.
		        );


  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );  
};

class Special : public Stmt {
 public:
  Special(string s, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Special(const Special &other);
  virtual ~Special(){};
  
  virtual void accept(IRVisitor *v) { v->visitSpecial(this); };
  virtual string tostring(); 
  virtual Special *clone() const;
  string special;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};



class Comment : public Stmt {
 public:
  Comment(const Comment &other);
  Comment(string s, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  virtual ~Comment() { };
  virtual void accept(IRVisitor *v) { v->visitComment(this); };
  virtual string tostring();
  virtual Comment *clone() const;
  string comment;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};



class ExpStmt: public Stmt {
 public:
  ExpStmt(Exp *e, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  ExpStmt(const ExpStmt &other);
  virtual ~ExpStmt() {};
  virtual string tostring();
  virtual void accept(IRVisitor *v) { v->visitExpStmt(this); };
  virtual ExpStmt *clone() const;
  Exp *exp;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};



class Call: public Stmt {
 public:
  Call(Exp *lval_opt, string fnname, vector<Exp*> params,
       address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Call(Exp *lval_opt, Exp *callee, vector<Exp *> params,
       address_t asm_ad = 0x0, address_t ir_ad = 0x0);

  Call(const Call &other);
  virtual ~Call() {};
  virtual string tostring();
  virtual void accept(IRVisitor *v) { v->visitCall(this); };
  virtual Call *clone() const;

  Exp* lval_opt;
  //  string fnname;
  Exp * callee;
  vector<Exp*> params;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};



class Return: public Stmt {
 public:
  Return(Exp *exp_opt,
         address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Return(const Return &other);
  virtual ~Return() {};
  virtual string tostring();
  virtual void accept(IRVisitor *v) { v->visitReturn(this); };
  virtual Return *clone() const;

  Exp* exp_opt;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};


class Func: public Stmt {
 public:
  Func(string fnname, bool has_rv, reg_t rt, 
           vector<VarDecl*> params, 
           bool external, vector<Stmt*> body,
           address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Func(const Func &other);
  virtual ~Func() {};
  virtual string tostring();
  virtual void accept(IRVisitor *v) { v->visitFunc(this); };
  virtual Func *clone() const;

  string fnname;
  bool has_rv;
  reg_t rt;
  vector<VarDecl*> params;
  bool external;
  vector<Stmt*> body;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};


class Assert: public Stmt {
 public:
  Assert(Exp *cond, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
  Assert(const Assert &other);
  virtual ~Assert() {};
  virtual string tostring();
  virtual void accept(IRVisitor *v) { v->visitAssert(this); };
  virtual Assert* clone() const { return new Assert(*this); };

  Exp *cond;

  virtual int symexe( HVC   hvc,
		      HExpr path_expr
		    );
};

string int_to_str( int i );
string int_to_hex( int i );
Label *mk_label();

extern "C" {
#endif // def __cplusplus
  extern stmt_type_t stmt_type(Stmt*);
  extern Exp* move_lhs(Stmt*);
  extern Exp* move_rhs(Stmt*);
  extern const char* label_string(Stmt*);
  extern const char* special_string(Stmt*);
  extern const char* comment_string(Stmt*);
  extern Exp* jmp_target(Stmt*);
  extern Exp* cjmp_cond(Stmt*);
  extern Exp* cjmp_ttarget(Stmt*);
  extern Exp* cjmp_ftarget(Stmt*);
  extern Exp* expstmt_exp(Stmt*);
  extern const char* vardecl_name(Stmt*);
  extern reg_t vardecl_type(Stmt*);
  extern int call_has_lval(Stmt*);
  extern Exp* call_lval_opt(Stmt*);
  extern Exp* call_fnname(Stmt*);
  extern Exp** call_params(Stmt*);
  extern int ret_has_exp(Stmt *s);
  extern Exp* ret_exp(Stmt *s);
  extern const char* func_name(Stmt *s);
  extern int func_has_rv(Stmt *s);
  extern reg_t func_rt(Stmt *s);
  extern Stmt** func_params(Stmt *s);
  extern int func_is_external(Stmt *s);
  extern Stmt** func_body(Stmt *s);
  extern Exp* assert_cond(Stmt*);
#ifdef __cplusplus
}
#endif

#endif
