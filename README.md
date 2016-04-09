Usage: \<TitleID TitleKey [-redown -redec -no3ds -nocia] or [-check]\> or [-deckey] or [-checkbin]    
\-deckey   : print keys from decTitleKeys.bin    
\-check    : checks if title id matches key    
\-checkbin : checks titlekeys from decTitleKeys.bin    
\-redown   : redownload content    
\-nodown   : don't download content, just print links    
\-redec    : re-attempt content decryption    
\-no3ds    : don't build 3DS file    
\-nocia    : don't build CIA file    

Requires [makerom](https://github.com/profi200/Project_CTR/releases) to be in the directory

If you are using the script itself instead of the compiled .exe, you will also need [Python 3](https://www.python.org/downloads/) to be installed, and [PyCrypto](https://pypi.python.org/pypi/pycrypto) to be installed.

The executable was created with the command `pyinstaller --onefile PlaiCDN.py`

This project was forked from [CDNto3DS](https://github.com/Relys/3DS_Multi_Decryptor/blob/master/to3DS/CDNto3DS/CDNto3DS.py) and includes expanded features and capabilities, including use on non windows platforms thanks to its reliance on PyCrypto instead of aescbc.
