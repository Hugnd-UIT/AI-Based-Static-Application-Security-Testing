#ifndef MEMORY_H
#define MEMORY_H

void copyData(const char* input);
void printLog(const char* message);
void useAfterFree();
void doubleFree();
void integerOverflow(short size, const char* input);

#endif
