# ClassyPP

Microsoft Visual Studio C++ Class information extraction.

## Description:

This plugin aims to aid in reverse engineering binaries compiled with MSVC and written in C++. 
Such binaries often contain extremely useful information about the classes and types used within it - Information that is invaluable 
to reverse engineering efforts.

This plugin performs 3 main actions:
	** RTTI Inspection **
	Search the exeutable for RTTI (Real-Time Type information) structures, and define the actual symbols 
	with types within the BinaryView, including demangled class names.
	
	** Resolve and Define Virtual-Function tables **
	Any C++ class will have its own vfTable within the executable.
	Identifying this vfTable is crucial in order to understand what functions belong to what class.
	
	This plugin takes this process one step further - Using Graph theory algorithms it will approximate 
	which class owns which function within a given vfTable. This is important because not all derived classes
	override functions within their base class, which means that the derived class vfTable might contain 
	functions that belong to the base class, and often times functions belonging to several different base 
	classes.
	
	** Define class types for known Classes **
	Using information extracted from the MSVC compiler (CL) regarding the memory layout of compiled classes it is possible
	to define the actual class type as it apears in memory - This type can later be applied to any function using the "This" pointer.
	Version 1.0 of this plugin contains memory layout information from many classes of the following libraries:
		- standard lib
		- Protobuf
		- Standard Template Library
		- CryptoPP
	The plugin will autoamtically define any class type in its database if the corresponding class is found to be resident in the executable.
	
	
## Limitations:
	- Supports MSVC Only
	- x64 architecture only
	- Version 1.0 does not support Virtual Inheritence (Support for this will be added in the future)

## License

This plugin is released under an [MIT license](./license).