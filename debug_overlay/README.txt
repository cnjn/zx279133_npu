ZX279133 debug tools (manual use only)

Run bin/ont-info --help for the list of read-only diagnostics. Run it
with the same privileges as your normal shell first; dmesg may require
additional privileges. Nothing here is started automatically. The tools
do not enable remote login, mount filesystems, or change flash.

Stock commands such as ip, ethtool and tcpdump remain where they were.
Extra binaries, if supplied at build time, are under bin/ as well. Do
not expose packet captures, kernel logs or debugging services to the WAN.
