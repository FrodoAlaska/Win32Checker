import re
import os
from pathlib import Path

def extract_win32_functions_from_markdown(md_file_path, output_file=None):
    # Enhanced pattern that looks for function calls specifically
    function_pattern = re.compile(
        r'(?:^|\s|\[|`|\(|\))'  # Preceded by whitespace or markdown syntax
        r'('
        r'(?:[A-Z][a-zA-Z0-9_]+[A-Z])\s*\([^)]*\)'  # FunctionName(params)
        r'|'
        r'::([A-Z][a-zA-Z0-9_]+)\s*\([^)]*\)'  # Class::Method(params)
        r'|'
        r'`([A-Z][a-zA-Z0-9_]+)\s*\([^)]*\)`'  # `FunctionName(params)`
        r'|'
        r'\[([A-Z][a-zA-Z0-9_]+)\]\s*\([^)]*\)'  # [`FunctionName`](params)
        r')'
    )
    
    # Additional patterns to exclude common non-functions
    exclude_patterns = re.compile(
        r'\b(?:WINAPI|APIENTRY|CALLBACK|LRESULT|DWORD|BOOL|HANDLE|HWND|'
        r'RECT|POINT|SIZE|WPARAM|LPARAM|ATOM|HDC|HBITMAP|HINSTANCE)\b',
        re.IGNORECASE
    )
    
    functions = set()
    
    try:
        with open(md_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Split content into lines for better context handling
            for line in content.split('\n'):
                # Skip lines that are headings or code blocks
                if line.startswith('#') or line.startswith('```'):
                    continue
                    
                # Find all function matches in this line
                for match in function_pattern.finditer(line):
                    # Check all capture groups for matches
                    for group_num in range(1, 5):
                        if match.group(group_num):
                            func = match.group(group_num)
                            # Extract just the function name (before parenthesis)
                            func_name = func.split('(')[0].strip()
                            
                            # Filter out excluded patterns and short names
                            if (not exclude_patterns.search(func_name) and 
                                len(func_name) > 2 and  # Exclude very short names
                                not func_name.endswith('_T') and  # Exclude macros
                                '_' not in func_name):  # Most functions don't have underscores
                                functions.add(func_name)
                                break
        
        sorted_functions = sorted(functions)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_functions))
            print(f"Extracted {len(sorted_functions)} functions to {output_file}")
        else:
            print(f"Found {len(sorted_functions)} functions:")
            print('\n'.join(sorted_functions))
            
        return sorted_functions
    
    except FileNotFoundError:
        print(f"Error: File not found - {md_file_path}")
        return []
    except Exception as e:
        print(f"Error processing file: {e}")
        return []

# Example usage:
if __name__ == "__main__":
    extract_win32_functions_from_markdown('win32_cheatsheet.md', 'win32_functions_list.txt')
