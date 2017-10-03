# **SquiddlyDiddlyEx Payload**

This is a Windows NT File System Octopus variant. This **malware** proof-of-concept is completely position independent, makes only kernel level calls, features resource infection mechanisms, pseudo-random name generation, and custom user-level API calls.

### **NOTE**
* Build Version 2.592 is a debugging build. It is NOT complete and will not compile.
* This code segment is targetted toward Windows 10 ONLY.
* Vertical Escalation is dependent on Windows 10 FodHelper.exe
* Removal of VxMoveFile
* Remodeling of API table loading (VxLoadNtDllFunctions, VxLoadKernel32Functions, etc)
* Current build has no run at start mechanism
* Temporary removal of AntiTraceEffect();
* Removal of any ANSI based functionality

### **TO-DO**
10/03/17
* Complete x64 VS conversion
* Complete bugs from previous project
* Introduce SYSTEM elevation procedures
* Introduce THREAD_CONTEXT switching from previous AntiTraceEffect
* Removal of additional user-mode functionality

8/28/17
* I am in the process of converting this project is x64
* I am in the process of creating this as VS project
* Bug fixes and to-do's from 8/16/2017

8/16/2017
* Implement FodHelper.exe cleanup routine
* Extract secondary module for file locking
* Reimplement run at start (enhanced++) (WMI?)
* Reimplement AntiTraceEffect w/ Thread context switching

8/02/17
* Make function specific calls for API table i.e. VxLoadNtDllFunctions, VxLoadKernel32Functions --done
* Remove usage of PE_DATA structure --done (modified)
* Implement Vertical escalation segment --done!

## Getting Started

THIS PROJECT IS NOT COMPLETE AND WILL NOT COMPILE AS OF 10/03/17

#### **Prerequisites**

THIS PROJECT IS NOT COMPLETE AND WILL NOT COMPILE AS OF 10/03/17

### **Infection/Keylogging**

    * RegisterRawInputData + GetRawInput
    * Current project contains no infection mechanism. This branch is PAYLOAD ONLY.

## Built With

* [Visual Studio 2017](https://www.visualstudio.com/vs/whatsnew/)
* [Microsoft Windows API](https://msdn.microsoft.com/en-us/library/aa383723(VS.85).aspx)

## Authors

* **Mathew A. Stefanowich** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* VxHeaven
* Blacksun Virus
* ReactOS
* winapi.freenode
* StackOverflow
* Mysoft - for roasting me/pushing me
* mr-satan - for roasting me/pushing me
* f4m1n3 - for everything
* john - for debugging help
* merced - for debugging help
* jDoodle.com - for saving me a ton of time
* md5decrypt.com - for saving me a ton of time
* mattifestation 
* malwarehunterteam
