#include <cstdio>
#include <sstream>
#include <string>
#include <fstream>
#include <unordered_set>
#include <vector>
#include <filesystem>

#include "win32_api_index.h"

/// -------------------------------------------------------------------------------------------------
/// DEFS

#define FLAGS_MAX 10

/// DEFS
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// CheckerEntry
struct CheckerEntry {
  std::filesystem::path file_name;

  std::vector<std::string> functions;
  std::vector<std::string> headers;

  int total_occurrences;
};
/// CheckerEntry
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// CheckerState
struct CheckerState {
  std::unordered_set<std::filesystem::path> exculsions;
  std::vector<CheckerEntry> entries;

  int total_headers   = 0; 
  int total_functions = 0;
};

static CheckerState s_checker;
/// CheckerState
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Private functions

static bool is_valid_file_extension(const std::filesystem::path& ext) {
  return ext == ".cpp" || 
         ext == ".h"   || 
         ext == ".hpp" || 
         ext == ".c";
}

/// Private functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Checker functions

void checker_check_file(const std::filesystem::path& path) {
  // We only care about source files
  if(!is_valid_file_extension(path.extension())) {
    return;
  }

  // We don't care about any exculsions
  if(s_checker.exculsions.find(path.parent_path()) != s_checker.exculsions.end()) {
    return;
  }

  // Open the source file file
  std::ifstream file(path);
  if(!file.is_open()) {
    printf("[CHECKER-ERROR]: Failed to open source file at \'%s\'\n", path.c_str());
    return;
  }

  // A new entry to the checker
  CheckerEntry entry;
  entry.file_name = path.filename();

  // Get the full source code string
  std::stringstream ss;
  ss << file.rdbuf();
  std::string source_code = ss.str(); 
  
  // Go through the headers index and try to find it in the source code
  for(auto& header : WIN32_HEADERS) {
    // Check against the functions index
    if(source_code.find(header) != std::string::npos) {
      entry.headers.push_back(header);
      s_checker.total_headers++;
    }
  }

  // Go through the function index and try to find it in the source code
  for(auto& func : WIN32_FUNCTIONS) {
    // Check against the functions index
    if(source_code.find(func) != std::string::npos) {
      entry.functions.push_back(func);
      s_checker.total_functions++;
    }
  }

  file.close();

  // Only add the entry if there are occurrences of Win32 in the file 
  if(!entry.functions.empty() || !entry.headers.empty()) {
    entry.total_occurrences = entry.headers.size() + entry.functions.size();
    s_checker.entries.push_back(entry);
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

  for(auto& entry : s_checker.entries) {
    printf("\n=== === %s === ===\n", entry.file_name.c_str()); 
    printf("\nWin32 functions amount  = %zu", entry.functions.size()); 
    printf("\nWin32 headers amount    = %zu", entry.headers.size()); 
    printf("\nWin32 total occurrences = %i", entry.total_occurrences); 
    printf("\n\n=== === %s === ===\n\n", entry.file_name.c_str()); 
  }

  printf("\n=== === Global === ===\n"); 
  printf("\nTotal functions amount  = %i", s_checker.total_functions); 
  printf("\nTotal headers amount    = %i", s_checker.total_headers); 
  printf("\n\n=== === Global === ===\n\n"); 
  
  printf("\n+++++ Win32Checker ++++++\n\n"); 
}

/// Checker functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Args functions

void args_show_help() {
  printf("\n\n----- Win32Checker: A tool to check all the win32 occurrences in a project -----\n\n"); 
  printf("Win32Checker usage: win32checker [options] <path>\n\n");
  printf("\twin32checker [--file -f]      = Run only a single source file through the checker.\n");
  printf("\twin32checker [--directory -d] = Iterate through a directory and run each source file through the checker.\n");
  printf("\twin32checker [--recursive -r] = Recursively iterate through a directory and run each source file through the checker.\n");
  printf("\twin32checker [--exclude -e]   = Exclude a certain file or directory from the search.\n");
  printf("\twin32checker [--help -h]      = Show this help screen.\n");
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
    "--exclude", "-e",
    "--help", "-h"
  };

  // Go through all the possible commands and compare
  for(int i = 1; i < argc; i++) {
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
    // Exclude 
    else if(flags[6] == argv[i] || flags[7] == argv[i]) {
      s_checker.exculsions.emplace(argv[++i]);
    }
    // Help 
    else if(flags[8] == argv[i] || flags[9] == argv[i]) {
      args_show_help();
      return 0;
    }
    // Error!
    else {
      printf("[CHECKER-ERROR]: The given argument \'%s\' is invalid\n", argv[i]);
      args_show_help();
      
      return -1;
    }
  }

  checker_list();
  return 0;
}

/// Args functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Main function

int main(int argc, char** argv) {
  // Parse the arguments and act accordingly
  return args_parse(argc, argv);
}

/// Main function
/// -------------------------------------------------------------------------------------------------
