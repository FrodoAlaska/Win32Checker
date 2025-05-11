#include <cstdio>
#include <string>
#include <fstream>
#include <unordered_set>
#include <vector>
#include <filesystem>

/// -------------------------------------------------------------------------------------------------
/// DEFS

#define FLAGS_MAX 8

/// DEFS
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// CheckerState
struct CheckerState {
  std::unordered_set<std::string> database;

  std::vector<std::string> functions;
  std::vector<std::string> headers;
};

static CheckerState s_checker;
/// CheckerState
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Checker functions

void checker_build_database() {
  s_checker.database.emplace("#include <windows.h>"); 
}

void checker_check_file(const std::string& path) {
  // Open the source file file
  std::ifstream file(path);
  if(!file.is_open()) {
    printf("[CHECKER-ERROR]: Failed to open source file file at \'%s\'\n", path.c_str());
    return;
  }

  // Go through every line and check againt the "database"
  std::string line; 
  while(std::getline(file, line)) {
    if(s_checker.database.find(line) != s_checker.database.end()) {
      s_checker.headers.push_back(line);
    }
  }

  file.close();
}

void checker_check_files(char** paths, const int begin, const int end) {
  for(int i = begin; i < end; i++) {
    // Open the source file file
    std::ifstream file(paths[i]);
    if(!file.is_open()) {
      printf("[CHECKER-ERROR]: Failed to open source file file at \'%s\'\n", paths[i]);
      return;
    }

    // Go through every line and check againt the "database"
    std::string line; 
    while(std::getline(file, line)) {
      if(s_checker.database.find(line) != s_checker.database.end()) {
        s_checker.headers.push_back(line);
      }
    }

    file.close();
  }
}

void checker_check_directory(const std::string& dir, const bool recursive) {
  if(!recursive) {
    for(auto& path : std::filesystem::directory_iterator(dir)) {
      checker_check_file(path.path().string());
    }
    
    return;
  }
  
  for(auto& path : std::filesystem::recursive_directory_iterator(dir)) {
    checker_check_file(path.path().string());
  }
}

void checker_list() {
  printf("\n\n+++++ Win32Checker ++++++\n"); 
  
  printf("\nWin32 functions amount  = %zu", s_checker.functions.size()); 
  printf("\nWin32 headers amount    = %zu", s_checker.headers.size()); 
  printf("\nWin32 total occurrences = %zu", s_checker.headers.size() + s_checker.functions.size()); 
  
  printf("\n\n+++++ Win32Checker ++++++\n\n"); 
}

/// Checker functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Args functions

void args_show_help() {
  printf("\n\n----- Win32Checker: A tool to check all the win32 occurrences in a project -----\n\n"); 
  printf("Win32Checker usage: \n");
  printf("\twin32checker [--file -f] [--directory -d] [--recursive -r] <path> = Run the given path through the checker\n");
  printf("\n\n----- Win32Checker: A tool to check all the win32 occurrences in a project -----\n\n"); 
}

int args_parse(int argc, char** argv) {
  if(argc <= 1) {
    printf("[CHECKER-ERROR]: Insufficient number of arguments given\n");
    return -1;
  }

  // All the possible flags
  std::string flags[FLAGS_MAX] = {
    "--file", "-f",
    "--directory", "-d", 
    "--recursive", "-r",
    "--help", "-h"
  };

  // Go through all the possible commands and compare
  for(int i = 1; i <= argc; i++) {
    // File 
    if(flags[0] == argv[i] || flags[1] == argv[i]) {
      checker_check_file(argv[++i]);
    }
    // Directory 
    else if(flags[2] == argv[i] || flags[3] == argv[i]) {
      checker_check_directory(argv[++i], false);
    }
    // Recursive 
    else if(flags[4] == argv[i] || flags[5] == argv[i]) {
      checker_check_directory(argv[++i], true);
    }
    // Help 
    else if(flags[6] == argv[i] || flags[7] == argv[i]) {
      args_show_help();
    }
    // Error!
    else {
      printf("[CHECKER-ERROR]: The given argument \'%s\' is invalid\n", argv[i]);
      args_show_help();

      return -1;
    }

    checker_list();
  }

  return 0;
}

/// Args functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Main function

int main(int argc, char** argv) {
  checker_build_database();

  // Parse the arguments and act accordingly
  return args_parse(argc, argv);
}

/// Main function
/// -------------------------------------------------------------------------------------------------
