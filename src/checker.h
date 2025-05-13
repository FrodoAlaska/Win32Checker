#pragma once

#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>

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
  std::vector<std::filesystem::path> source_files;
  std::unordered_set<std::filesystem::path> exculsions;
  
  std::vector<CheckerEntry> entries;

  std::filesystem::path working_dir      = "";
  std::filesystem::path output_file_name = "output.txt";

  int total_headers   = 0; 
  int total_functions = 0;
  bool is_verbose     = false;
};
/// CheckerState
/// -------------------------------------------------------------------------------------------------

/// -------------------------------------------------------------------------------------------------
/// Checker functions

bool checker_init(CheckerState* out_state, int argc, char** argv);

void checker_check_file(CheckerState& state, const std::filesystem::path& path);

void checker_save_output(CheckerState& state);

void checker_list(CheckerState& state);

/// Checker functions
/// -------------------------------------------------------------------------------------------------
