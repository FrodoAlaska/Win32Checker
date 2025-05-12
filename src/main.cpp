#include "checker.h"

int main(int argc, char** argv) {
  if(!checker_init(argc, argv)) {
    return -1;
  }
  
  checker_save_output();
  checker_list();

  return 0;
}
