This is a python script which can take a title id and title key as input to create an installable CIA by downloading and decrypting eShop content.

Usage: CDNto3DS.py <TitleID TitleKey [-redown -redec -no3ds -nocia] or [-check]> or [-deckey] or [-checkbin]    
\-deckey   : print keys from decTitleKeys.bin    
\-check    : checks if title id matches key    
\-checkbin : checks titlekeys from decTitleKeys.bin    
\-redown   : redownload content    
\-nodown   : don't download content, just print links    
\-redec    : re-attempt content decryption    
\-no3ds    : don't build 3DS file    
\-nocia    : don't build CIA file    
