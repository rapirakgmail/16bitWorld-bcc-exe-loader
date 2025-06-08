#include <stdio.h>
#include <stdlib.h>
#include <dos.h>  // For Turbo/Borland compatibility
#include <mem.h>

int mydata;
void f()
{
  scanf("%d  ,  %d",&mydata);
}

void main()
{

//  int *m = (int*)malloc(1000);

  printf("get  %d",1);
  f();
  printf("hellow  %d",1);
  printf("get  %d",1);
  f();
}