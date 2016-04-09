Use [3dsdb.com](http://www.3dsdb.com/) to find title ids; you're on your own for the keys.    
Requires [makerom](https://github.com/profi200/Project_CTR/releases) to be in the directory    
___

Usage: `<TitleID TitleKey [-redown -redec -no3ds -nocia] or [-check]> or [-deckey] or [-checkbin]`    
\-deckey   : print keys from decTitleKeys.bin    
\-check    : checks if title id matches key    
\-checkbin : checks titlekeys from decTitleKeys.bin    
\-redown   : redownload content    
\-nodown   : don't download content, just print links    
\-redec    : re-attempt content decryption    
\-no3ds    : don't build 3DS file    
\-nocia    : don't build CIA file    

___

Examples (note this is not the correct key as that is copyrighted):    
+ `PlaiCDN.exe 000400000014F200 abb5c65ecaba9bcd29d1bfdf3f64c285`
  + this would create a .CIA and .3DS file for "Animal Crossing: Happy Home Designer"
+ `PlaiCDN.exe 000400000014F200 abb5c65ecaba9bcd29d1bfdf3f64c285 -check`
  + this would check if the key (abb5c65ecaba9bcd29d1bfdf3f64c285) for "Animal Crossing: Happy Home Designer" is correct (it's not)
+ `PlaiCDN.exe 000400000014F200 abb5c65ecaba9bcd29d1bfdf3f64c285 -redown -no3ds`
  + this would create a .CIA file after redownloading previously downloaded encrypted files for "Animal Crossing: Happy Home Designer"
+ `PlaiCDN.exe -checkbin`
  + this would check all keys in `decTitleKeys.bin` to see if they match their titles

___

If you are using the script itself instead of the compiled .exe, you will also need [Python 3](https://www.python.org/downloads/) to be installed, and [PyCrypto](https://pypi.python.org/pypi/pycrypto) to be installed.

The executable was created with the command `pyinstaller --onefile PlaiCDN.py`
