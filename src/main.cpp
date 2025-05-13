#include "checker.h"

int main(int argc, char** argv) {
  CheckerState state;
  if(!checker_init(&state, argc, argv)) {
    return -1;
  }
  
  checker_save_output(state);
  checker_list(state);

  return 0;
}
