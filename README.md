# Win32Checker 

A CLI application that checks and returns the amount of Win32 "dependency" in a project. It counts all possible Win32 functions and headers mentioned in a project or a directory. It takes into account any `.h`, `.hpp`, `.cpp`, or `.c` source files.

## Build Instructions

Like any other C++ project out there, this project uses CMake for its build system. It's only a couple of files, using only `C++17` features. No dependencies at all. However, the project does depend on the `win32_functions_list.txt` file, so make sure to have it at the same place as the executable.

Either way, if you run the commands below, you should be able to compile Win32Checker. 


```bash
mkdir build && cd build 
cmake ..

# On Linux
make

# On Windows
cmake --build .
```
## Usage 

Below you'll find the flags the Win32Checker executable accepts.

```
win32checker [--file -f]      = Run only a single source file through the checker.
win32checker [--directory -d] = Iterate through a directory and run each source file through the checker.
win32checker [--recursive -r] = Recursively iterate through a directory and run each source file through the checker.
win32checker [--exclude -e]   = Exclude a certain file or directory from the search.
win32checker [--help -h]      = Show this help screen.
```

And, as you can see, they are pretty self-explanatory. Here's a simple example using Win32Checker to check a project name `Win32App`.

```
win32checker --recursive "path/to/Win32App/src"
```

You can also check just a single source file:


```
win32checker --file "path/to/Win32App/src/main.cpp"
```

Or multiple all at once: 


```
win32checker --file "path/to/Win32App/src/main.cpp" "path/to/Win32App/window.cpp"
```

When Win32Checker is done searching, it will generate the results in the console like such.


```
+++++ Win32Checker ++++++

=== === main.cpp === ===

Win32 functions amount  = 10
Win32 headers amount    = 1
Win32 total occurrences = 11

=== === main.cpp === ===

=== === Global === ===

Total functions amount  = 11
Total headers amount    = 1

=== === Global === ===

+++++ Win32Checker ++++++
```

We can also exclude certain directories from the search:


```
win32checker --exclude "path/to/Win32App/include" "path/to/Win32App/thirdparty" --recursive "path/to/Win32App"
```

Here, Win32Checker will ignore the directory "include" in "Win32App".

## Installation 

If you wish to access Win32Checker at a global level and anywhere in your system, you can run the command below on Linux to achieve that:


```bash
sudo make install
```

On Windows, you can either build Win32Checker somewhere and leave it there or place it somewhere else. It doesn't really matter. What matters is that you should add the directory where Win32Checker lives to your enviornment variables.
