# ClassyPP

Microsoft Visual Studio C++ Class information extraction.

## Description:

This plugin aims to aid in reverse engineering binaries compiled with MSVC and written in C++. 
Such binaries often contain extremely useful information about the classes and types used within it - Information that is invaluable 
to reverse engineering efforts.

This plugin performs 3 main actions:

**RTTI Inspection**

Search the executable for RTTI (Real-Time Type information) structures, and define the actual symbols 
with types within the BinaryView, including demangled class names.

-BEFORE-

![RTTI Inspection - Before](https://user-images.githubusercontent.com/34336222/171192716-bafebbb8-0684-47ef-94be-30de176b89a1.png)

-AFTER-

![RTTI Inspection - After](https://user-images.githubusercontent.com/34336222/171192825-c004b21e-96f9-44f4-9f50-4400a10fc01a.png)


**Resolve and Define Virtual-Function tables**

Any C++ class will have its own vfTable within the executable.
Identifying this vfTable is crucial in order to understand what functions belong to what class.

This plugin takes this process one step further - Using Graph theory algorithms it will approximate 
which class owns which function within a given vfTable. This is important because not all derived classes
override functions within their base class, which means that the derived class vfTable might contain 
functions that belong to the base class, and often times functions belonging to several different base 
classes.

-BEFORE-

![vfTable - Before](https://user-images.githubusercontent.com/34336222/171192911-155679ca-c078-41a4-9faf-c85f552b9acc.png)


-AFTER-

![vfTable - After](https://user-images.githubusercontent.com/34336222/171192938-75f4397e-5013-477d-b761-be4a06f509ff.png)

**Detect and Define Constructor functions**

Base on information obtained in the preceeding steps, it is possible to locate suspected constructor function for the 
various detected classes.
The plugin will either annotate the suspected constructor with a comment or change the name of the function to reflect
the high probability of it being a constructor.


**Define class types for known Classes**

Using information extracted from the MSVC compiler (CL) regarding the memory layout of compiled classes it is possible
to define the actual class type as it apears in memory - This type can later be applied to any function using the "This" pointer.
Version 1.0 of this plugin contains memory layout information from many classes of the following libraries:
  - standard lib
  - Protobuf
  - Standard Template Library
  - CryptoPP
The plugin will autoamtically define any class type in its database if the corresponding class is found to be resident in the executable.

![class definition](https://user-images.githubusercontent.com/34336222/171192986-05e2f215-d02f-4800-ac4e-66e37403c9b0.png)

## Installation

This plugin installs as a normal binja plugin - just clone it into the plugins' directory.
Edit the Config.py file for values suitable to your environment.
	
## Limitations:
	- Supports MSVC Only
	- x86 32\64 bit architecture only
	- Currently no support for Multiple Virtual Inheritence (Support for this will be added in the future)

## Acknowledgment

This plugin uses the Demumble project in order to demangle C++ symbols - https://github.com/nico/demumble.

## License

This plugin is released under an [MIT license](./license).
