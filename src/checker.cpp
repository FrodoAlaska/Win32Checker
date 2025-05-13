#include "checker.h"
#include "exporters.h"
#include "win32_api_index.h"

#include <cstdio>
#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <fstream>

/// -------------------------------------------------------------------------------------------------
/// DEFS

#define VALID_OPTIONS_MAX 8

/// DEFS
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// ArgsToken 
enum ArgsToken {
  ARGS_TOKEN_WORKING_DIR = 0,
  ARGS_TOKEN_FILE,
  ARGS_TOKEN_DIRECTORY, 
  ARGS_TOKEN_RECURSIVE,
  ARGS_TOKEN_EXCLUDE,
  ARGS_TOKEN_OUTPUT,
  ARGS_TOKEN_HELP,
  ARGS_TOKEN_VERBOSE,
  ARGS_TOKEN_LITERAL, 
  ARGS_TOKEN_EOF,
};
/// ArgsToken 
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Args 
struct Args {
  ArgsToken token; 

  std::string option; 
  std::string alt_option;
};
/// Args
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Private functions

static bool is_valid_file_extension(const std::filesystem::path& ext) {
  return ext == ".cpp" || 
         ext == ".h"   || 
         ext == ".hpp" || 
         ext == ".c";
}

static bool is_arg_valid(char* argv, const Args& arg) {
  return (arg.option == argv) || (arg.alt_option == argv);
}

void show_help() {
  printf("\n\n----- Win32Checker: A tool to check all the win32 occurrences in a project -----\n\n"); 
  printf("Win32Checker usage: win32checker [options] <path>\n\n");
  printf("\twin32checker [--working-dir -wd] = The path to prepend to any subsequent paths.\n");
  printf("\twin32checker [--file -f]         = Run only a single source file through the checker.\n");
  printf("\twin32checker [--directory -d]    = Iterate through a directory and run each source file through the checker.\n");
  printf("\twin32checker [--recursive -r]    = Recursively iterate through a directory and run each source file through the checker.\n");
  printf("\twin32checker [--exclude -e]      = Exclude a certain file or directory from the search.\n");
  printf("\twin32checker [--output -o]       = Specify a certain file to write results to.\n");
  printf("\twin32checker [--verbose -v]      = Print out the results in realtime.\n");
  printf("\twin32checker [--help -h]         = Show this help screen.\n");
  printf("\n\n----- Win32Checker: A tool to check all the win32 occurrences in a project -----\n\n"); 
}

static void lex_arguments(int argc, char** argv, std::vector<Args>* out_args) {
  if(argc < 2) {
    printf("[CHECKER-ERROR]: No arguments passed\n");
    show_help();

    return;
  }

  // We just allocate a buffer priori to avoid any slowdowns.
  out_args->reserve(argc);

  Args valid_options[VALID_OPTIONS_MAX] = {
    {ARGS_TOKEN_WORKING_DIR, "--working-dir", "-wd"},
    {ARGS_TOKEN_FILE, "--file", "-f"},
    {ARGS_TOKEN_DIRECTORY, "--directory", "-d"}, 
    {ARGS_TOKEN_RECURSIVE, "--recursive", "-r"},
    {ARGS_TOKEN_EXCLUDE, "--exclude", "-e"},
    {ARGS_TOKEN_OUTPUT, "--output", "-o"},
    {ARGS_TOKEN_HELP, "--help", "-h"},
    {ARGS_TOKEN_VERBOSE, "--verbose", "-v"}
  };

  // @NOTE: This is potentially very slow
  for(int i = 1; i < argc; i++) {
    bool is_found = false;
    
    // Check if any of the arguments are flags
    for(int j = 0; j < VALID_OPTIONS_MAX; j++) {
      if(is_arg_valid(argv[i], valid_options[j])) {
        out_args->push_back(valid_options[j]);
        is_found = true;

        break;
      }
    }
    
    // Otherwise, it's probably a string literal
    if(!is_found) {
      out_args->push_back(Args{ARGS_TOKEN_LITERAL, argv[i]});
    }
  }

  // We're done now
  out_args->push_back(Args{ARGS_TOKEN_EOF});
}

void check_directory(CheckerState* state, const std::string& dir, const bool recursive) {
  if(!recursive) {
    for(auto& path : std::filesystem::directory_iterator(state->working_dir / dir)) {
      if(!is_valid_file_extension(path.path().extension())) {
        continue;
      }

      state->source_files.push_back(path.path());
    }
    
    return;
  }
  
  for(auto& path : std::filesystem::recursive_directory_iterator(state->working_dir / dir)) {
    if(!is_valid_file_extension(path.path().extension())) {
      continue;
    }

      state->source_files.push_back(path.path());
  }
}

void exclude_directory(CheckerState* state, const std::string& dir) {
  for(auto& path : std::filesystem::recursive_directory_iterator(state->working_dir / dir)) {
    if(!is_valid_file_extension(path.path().extension())) {
      continue;
    }

    state->exculsions.emplace(path.path());
  }
}

static void file_token_check(CheckerState* state, std::vector<Args>& args, int* current_index) {
  Args* current_arg = &args[*current_index + 1];

  while(current_arg->token == ARGS_TOKEN_LITERAL) {
    std::filesystem::path path = current_arg->option;
    if(is_valid_file_extension(path.extension())) {
      state->source_files.push_back(path);
    }

    *current_index += 1;
    current_arg     = &args[*current_index + 1];
  }
}

static void directory_token_check(CheckerState* state, std::vector<Args>& args, int* current_index, const bool recursive) {
  Args* current_arg = &args[*current_index + 1];

  while(current_arg->token == ARGS_TOKEN_LITERAL) {
    check_directory(state, current_arg->option, recursive);

    *current_index += 1;
    current_arg     = &args[*current_index + 1];
  }
}

static void exclude_dir_token(CheckerState* state, std::vector<Args>& args, int* current_index) {
  Args* current_arg = &args[*current_index + 1];

  while(current_arg->token == ARGS_TOKEN_LITERAL) {
    exclude_directory(state, current_arg->option);

    *current_index += 1;
    current_arg     = &args[*current_index + 1];
  }
}

bool parse_arguments(CheckerState* out_state, int argc, char** argv) {
  std::vector<Args> args; 
  lex_arguments(argc, argv, &args);

  for(int i = 0; i < args.size(); i++) {
    Args* current_arg = &args[i]; 

    switch(current_arg->token) {
      case ARGS_TOKEN_WORKING_DIR:
        out_state->working_dir = args[++i].option;
        break;
      case ARGS_TOKEN_FILE:
        file_token_check(out_state, args, &i);
        break;
      case ARGS_TOKEN_DIRECTORY: 
        directory_token_check(out_state, args, &i, false);
        break;
      case ARGS_TOKEN_RECURSIVE:
        directory_token_check(out_state, args, &i, true);
        break;
      case ARGS_TOKEN_EXCLUDE:
        exclude_dir_token(out_state, args, &i);
        break;
      case ARGS_TOKEN_OUTPUT:
        out_state->output_file_name = args[++i].option;
        break;
      case ARGS_TOKEN_HELP:
        show_help();
        return false;
      case ARGS_TOKEN_VERBOSE:
        out_state->is_verbose = true;
        break;
      case ARGS_TOKEN_LITERAL: 
      case ARGS_TOKEN_EOF:
        break;
      default:
        break;
    }
  }

  return true;
}

/// Private functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Checker functions

bool checker_init(CheckerState* out_state, int argc, char** argv) {
  if(!parse_arguments(out_state, argc, argv)) {
    return false;
  }

  // Check all the included source files
  for(auto& file : out_state->source_files) {
    checker_check_file(*out_state, file);
  }

  return true;
}

void checker_check_file(CheckerState& state, const std::filesystem::path& path) {
  // We don't care about any exculsions
  if(state.exculsions.find(path) != state.exculsions.end()) {
    return;
  }

  // Open the source file file
  std::ifstream file(path);
  if(!file.is_open()) {
    printf("[CHECKER-ERROR]: Failed to open source file at \'%s\'\n", path.string().c_str());
    return;
  }
 
  if(state.is_verbose) {
    printf("[CHECKER-TRACE]: Checking in file \'%s\'...\n", path.string().c_str());
  }

  // A new entry to the checker
  CheckerEntry entry;
  entry.file_name = path;

  // Get the full source code string
  std::stringstream ss;
  ss << file.rdbuf();
  std::string source_code = ss.str(); 
  
  // Go through the headers index and try to find it in the source code
  for(auto& header : WIN32_HEADERS) {
    // Check against the functions index
    if(source_code.find(header) != std::string::npos) {
      entry.headers.push_back(header);
      state.total_headers++;
    }
  }

  // Go through the function index and try to find it in the source code
  for(auto& func : WIN32_FUNCTIONS) {
    // Check against the functions index
    if(source_code.find(func) != std::string::npos) {
      entry.functions.push_back(func);
      state.total_functions++;
    }
  }

  file.close();

  // Only add the entry if there are occurrences of Win32 in the file 
  if(!entry.functions.empty() || !entry.headers.empty()) {
    entry.total_occurrences = entry.headers.size() + entry.functions.size();
    state.entries.push_back(entry);
  }
}

void checker_save_output(CheckerState& state) {
  // Export/save to the specific file format
  std::filesystem::path ext = state.output_file_name.extension(); 
  if(ext == ".txt") {
    export_to_txt(state);
  }
  else if (ext == ".csv") {
    export_to_csv(state);
  }
  else {
    printf("[CHECKER-ERROR]: The output file given \'%s\' is an unsupported format\n", state.output_file_name.string().c_str());
    return;
  }
  
  printf("[CHECKER-INFO]: Saved results at \'%s\'\n", state.output_file_name.string().c_str());
}

void checker_list(CheckerState& state) {
  if(!state.is_verbose) {
    return;
  }

  printf("\n\n+++++ Win32Checker ++++++\n"); 

  for(auto& entry : state.entries) {
    printf("\n=== === %s === ===\n", entry.file_name.string().c_str()); 

    printf("\nWin32 functions amount = %zu\n", entry.functions.size()); 
    for(auto& func : entry.functions) {
      printf(" - %s\n", func.c_str()); 
    }

    printf("\nWin32 headers amount = %zu\n", entry.headers.size()); 
    for(auto& header : entry.headers) {
      printf(" - %s\n", header.c_str()); 
    }

    printf("\nWin32 total occurrences = %i", entry.total_occurrences); 
    printf("\n\n=== === %s === ===\n\n", entry.file_name.string().c_str()); 
  }

  printf("\n=== === Global === ===\n"); 
  printf("\nTotal functions amount  = %i", state.total_functions); 
  printf("\nTotal headers amount    = %i", state.total_headers); 
  printf("\n\n=== === Global === ===\n"); 
  
  printf("\n+++++ Win32Checker ++++++\n\n"); 
}

/// Checker functions
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Args functions

/// Args functions
/// -------------------------------------------------------------------------------------------------
