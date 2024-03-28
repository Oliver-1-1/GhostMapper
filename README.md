# GhostMapper

## 1.1 Introduction: 
You may or may not have spotted 3 drivers in your Windows system that start with the prefix "dump_". These virtual drivers are special and are often referred to as ghost drivers.
These ghost drivers are used to have a valid and noncorrupted image when a crash happens. When a crash occurs some drivers that need to save data to the disk may be the drivers that caused the crash, therefore
we have a replica of those drivers with the dump_ prefix with the original driver being without the prefix. If we want to save important data to the disk before a crash the ghost drivers can be activated and used.
The ghost drivers are monitored and managed by the crashdmp.sys driver and in that driver are some interesting information that I will take up later.
In reality, the ghost driver is rarely used but could be abused and modified to anyone's liking.

## 1.2 Technical details:
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

## 1.3 Crashdump.sys:
As stated before all ghost drivers have the same prefix. What if we could somehow patch this prefix before all the ghost drivers are loaded into memory?

![Code: ](https://imgur.com/AvMTx7b.png "Code: ")

With the right signature[2] we could easily patch this out during boot to load our custom-made ghost drivers. Or patch existing ghost drivers since they are inactive. More info on this later.
The result of this could look something like this: 
 
![Code: ](https://imgur.com/d5FR3AF.png "Code: ")

This is of course not enough to be able to hide your driver. All ghost drivers are saved in a linked list in Crashdump.sys. In Crashdump we could find the struct called DUMP_CONTROL_BLOCK which
has a member with the type DUMP_STACK_CONTEXT[3]. In DUMP_STACK_CONTEXT is a linked list with all the dump drivers with their respective file objects.

## 2.1 Code - PoC 
So I created a PoC mapper of this that will map your driver inside one of these ghost drivers. This will result in you having a driver in signed memory.

The mapper code is taken from xigmapper since this is just a POC and is to show the concept. Since the page protection does not match with your driver I changed the pte to the appropriate protection to be
able to run the driver. So .text section will have nx = false and rw = false; .data section will have nx=true and rw=true;
I start out with zeroing out the whole driver to prevent bugs then I patch in my driver and change page protection.

This can easily be combined with a boot mapper and that way you could implement what's suggested in section 1.3. 

Update: 
to provide a more 'realistic / ready to use' PoC we also provide 'GhostMapperUM' , which will map your unsigned driver over a ghost driver exploiting the iqvw64e.sys Intel driver from UM
(thanks to TheCruz for some of the utils taken from kdmapper) 

## 2.2 Code - GhostMapperUM 
intended to provide a more realistic / "ready to use" PoC , doing eveyrthing from UserMode thanks to Kdmapper's utils for exploiting the iqvw64e.sys Intel driver 

the mapper marks the target ghost driver as RWX (via pte manipulation) , writes your target driver over it and executes it's entry through ZwAddAtom hook 

code to restore the changes (rewriting the original ghost driver image and restroing page table entries)  is included and is currently called after the target driver returns from it's DriverEntry (since the PoC driver we map does nothing beyond that)

 of course , if you create a thread you'd have to sync the mapper and your driver to know when your mapped driver has actually finished it's job , only then restore the modifications !

a trivial way to detect this method will be to compare section permissions and data on disk vs in memory -  will not match whilst the mapped driver is active.

having said that , since ghost drivers point to an invalid path on disk some integrity checkers and anti cheats tend to simply skip them : ) 


## Resources:
[1] = https://crashdmp.wordpress.com/

[2] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x8D\x41\x03", "xxx????xxxx";

[3] = https://systemroot.gitee.io/pages/apiexplorer/d0/d6/iop_8h.html

