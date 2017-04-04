/*
    Copyright (c) 2016 Meiji University Information Security Laboratory (SaitoLab)

    Released under the MIT license
    http://opensource.org/licenses/mit-license.php

    We developed this software by making some changes and additions to Shinichiro Hamaji's one, which is also released under the MIT license.
    The original copyright and license are shown below: 

    Copyright (c) 2015 Shinichiro Hamaji

    Released under the MIT license
    http://opensource.org/licenses/mit-license.php

    Here is Shinichiro Hamaji's license page: 
    https://github.com/shinh/tel_ldr/blob/master/LICENSE
*/

#include<stdio.h>
#include<stdarg.h>
#include<stdlib.h>
#include"print.h"

void el_error(const char *msg){
  return;
  fprintf(stderr, "%s", msg);
  exit(1);
}

void el_print(const char *format, ...){
  return;
  va_list ap;
  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
}
