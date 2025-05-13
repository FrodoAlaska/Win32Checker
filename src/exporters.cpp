#include "exporters.h"
#include "checker.h"

#include <fstream>
#include <cstdio>

/// -------------------------------------------------------------------------------------------------
/// Exporter functions

void export_to_txt(CheckerState& state) {
  // Open the the output file first
  std::ofstream file(state.output_file_name, std::ios::out | std::ios::trunc);
  if(!file.is_open()) {
    printf("[CHECKER-ERROR]: Failed to open the output file at \'%s\'\n", state.output_file_name.string().c_str());
    return;
  }
  
  for(auto& entry : state.entries) {
    file << '\n' << (entry.file_name.filename()) << ": \n";

    file << "\nWin32 functions amount = " << entry.functions.size() << '\n'; 
    for(auto& func : entry.functions) {
      file << " - " << func << '\n';
    }

    file << "\nWin32 headers amount = " << entry.headers.size() << '\n'; 
    for(auto& header : entry.headers) {
      file << " - " << header << '\n';
    }

    file << "\nWin32 total occurrences = " << entry.total_occurrences << "\n\n"; 
  }

  file << "\nTotal functions amount  = " << state.total_functions << '\n'; 
  file << "\nTotal headers amount    = " <<  state.total_headers << '\n'; 
}

void export_to_csv(CheckerState& state) {
  // Open the the output file first
  std::ofstream file(state.output_file_name, std::ios::out | std::ios::trunc);
  if(!file.is_open()) {
    printf("[CHECKER-ERROR]: Failed to open the output file at \'%s\'\n", state.output_file_name.string().c_str());
    return;
  }

  // Defining the columns
  file << "Source file," << "Total occurrences," << "Total functions," << "Total headers," << '\n'; //"Headers," << "Functions," << '\n';
  
  // Adding each entry
  for(auto& entry : state.entries) {
    file << entry.file_name << ',' << entry.total_occurrences << ',' << entry.functions.size() << ',' << entry.headers.size() << '\n';
  }

  // Global settings
  file << "Total" << ',' << (state.total_functions + state.total_headers) << ',' << state.total_functions << ',' << state.total_headers << '\n';
}

/// Exporter functions
/// -------------------------------------------------------------------------------------------------
