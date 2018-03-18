# pee-e-eye
this script allows the user to perform a quick and basic static analysis on a portable executable file



this **python** script uses the **pefile** and **peutils** libraries to dump the import/export tables, section names, resource strings and ascii strings. the script is also capable of identifying a packer if one was used. to use this functionality, the user would have to place a signature database in the same directory as pee-ee-eye.py. The creators of **PEiD** have one such file available [here](http://woodmann.com/BobSoft/Files/Other/UserDB.zip).

#### dependencies####

[pefile](https://github.com/erocarrera/pefile)