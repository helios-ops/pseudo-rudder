#!/bin/bash
#NOTE : OPERATION under vine/libasmir/src
cd libasmir/src

g++ -DHAVE_CONFIG_H -I. -I../../libasmir -I../../VEX//pub -I./include -fPIC -g -O2 -MT exp.o -MD -MP -MF .deps/exp.Tpo -c -o exp.o `test -f './ir/exp.cpp' || echo './'`./ir/exp.cpp

g++ -DHAVE_CONFIG_H -I. -I../../libasmir -I../../VEX//pub -I./include -fPIC -g -O2 -MT stmt.o -MD -MP -MF .deps/stmt.Tpo -c -o stmt.o `test -f './ir/stmt.cpp' || echo './'`./ir/stmt.cpp

# rebuild libasmir.a
ar cru libasmir.a debug.o objdump.o asm_program.o vexmem.o irtoir.o irtoir-i386.o irtoir-arm.o irtoir_c.o vexir.o gen_thunks.o stmt.o stmt_c.o exp.o exp_c.o translate.o 
ranlib libasmir.a
rm ir/libasmir.a
cp libasmir.a ir/

cd ir
g++ -I.. -I../include  -c GetTemuData.o GetTemuData.cpp

cd ..
g++ -DHAVE_CONFIG_H -I. -I../../libasmir -I../../VEX//pub -I./include -fPIC -g -O2 -c -o SymExe.o ./ir/SymExe.cpp

cp SymExe.o ir/


g++ -DHAVE_CONFIG_H -I. -I../../libasmir    -I../../VEX//pub -I./include -fPIC -g -O2 i386_reg_init.o  -c -o i386_reg_init.o `test -f './ir/i386_reg_init.cpp' || echo './'`./ir/i386_reg_init.cpp

cp i386_reg_init.o ir/



cd ir
# Final making the IR_SymExe.so
g++ IR_operation.cpp H_STP_stub.cpp label_queue.cpp GetTemuData.o SymExe.o ../i386_reg_init.o -I../.. -I../../apps -I../include -I../../../VEX//pub -g -O2 -L. -L../../src -L../../../VEX/ -g -O2 -L../../src -L../../../VEX/ -shared -fPIC -o IR_SymEXE.so -lasmir -lvex -lbfd -liberty -lopcodes -liberty -Xlinker -rpath ./


