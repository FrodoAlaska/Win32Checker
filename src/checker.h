#pragma once

#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>

/// -------------------------------------------------------------------------------------------------
/// Checker functions

bool checker_init(int argc, char** argv);

void checker_check_file(const std::filesystem::path& path);

void checker_save_output();

void checker_list();

/// Checker functions
/// -------------------------------------------------------------------------------------------------
