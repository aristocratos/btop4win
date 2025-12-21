## v1.0.5
* Updated: LibreHardwareMonitor to latest version (0.9.4)
* Added: Better detection of GPU total memory
* Added: Add option for narrow and wide cpu views, @samiksome92
* Fixed: Addressed potential race condition in exit handler, by @bot984397

## v1.0.4

* Fixed: Gpu total memory will now default to highest recorded usage if not detected.
* Added: Config option to override gpu total memory.
* Added: New theme paper, by @s6muel

## v1.0.3

* Fixed: Config not saving when quittting by closing with window controls
* Changed: Ignore warning for WMI CoInitializeSecurity() when it's already have been called
* Fixed: Core mapping for cpu temps
* Fixed: `io_graph_speeds` config setting

## v1.0.2

* Fixed: Tools::hostname() and Tools::username()
* Fixed: Net graphs sync rescaling
* Fixed: Memory values not clearing properly when not in graph mode in mem box
* Changed: Stalls only force quit if over 1 minute, (disks waking up seems to be causing short stalls)
* Fixed: Cpu clock for Ryzen Mobile

## v1.0.1

* Changed: Switched from using OpenHardwareMonitor to LibreHardwareMonitor DLL import
* Fixed: CPU/GPU temps for Ryzen mobile CPUs
* Fixed: More fixes for Ryzen mobile

## v1.0.0

* First release
