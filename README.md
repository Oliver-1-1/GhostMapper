# GhostMapper

## Introduction: 
You may or may not spotted 3 drivers in your Windows system that start with the prefix "dump_". These virtual drivers are special and are often referred to as ghost drivers.
These ghost drivers are used to have a valid and noncorrupted image when a crash happens. When a crash occurs some drivers that need to save data to the disk may be the drivers that caused the crash, therefore
we have a replica of those drivers with the dump_ prefix with the original driver being without the prefix. If we want to save important data to the disk before a crash the ghost drivers can be activated and used.
The ghost drivers are monitored and managed by the crashdmp.sys driver and in that driver are some interesting information that I will take up later.
In reality, the ghost driver is rarely used but could be abused and modified to anyone's liking.

## Technical details:
There are ways to create your own dump driver which will later be a ghost driver. It's not well documented by Microsft but there are a few criteria that need to be fulfilled for the driver to be loaded.

* As with any other driver it will need a valid certificate to be loaded.
* The driver entry will take in these arguments with structs that needs to be populated:
DriverEntry(PFILTER_EXTENSION FilterExtension, FILTER_INITIALIZATION_DATA FilterInitialization);
The FilterInitialization struct is supposed the be populated with different callbacks that are used when the crash happens.

  * Dump_Start()

  * Dump_Write()

  * Dump_Read()

  * Dump_Finish() 
  * Dump_Unload()
  
  To read about these callbacks and their use case look in resources[1].

* You will have to register your new driver in the Windows registry. The path is Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\DumpFilters.
  Be careful when modifying this since it may result in crashdmp.sys attempting to load the driver as a dump driver and crashing the system at boot. Which makes it hard to recover.

This was a simplified version of how the ghost and dump drivers work and I recommend reading this blog[1].

##Crashdump.sys:
As stated before all ghost drivers have the same prefix. What if we could somehow patch this prefix before all the ghost drivers are loaded into memory?

![Code: ](https://cdn.discordapp.com/attachments/892418440298631238/1168890126814937108/Screenshot_2023-10-31_132948.png?ex=655368c3&is=6540f3c3&hm=2d08ee9ec7403d4a1c82921c52dfaf9c59835a3e3c43b0e2cbbd3e119f36864c& "Code: ")

With the right signature[2] we could easily path this out during boot to load our custom-made ghost drivers. Or straight-patch up patch existing ghost drivers since they are inactive. More info on this later.
The result of this could look something like this: 
 
![Code: ](https://cdn.discordapp.com/attachments/892418440298631238/1168891674706059325/Screenshot_2023-10-31_133757.png?ex=65536a34&is=6540f534&hm=0034175819c55481b82391ac26c8ae0332d486a16b83300b25d6563d739c553f& "Code: ")





## Resources:
[1] = https://crashdmp.wordpress.com/
[2] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x8D\x41\x03", "xxx????xxxx";
