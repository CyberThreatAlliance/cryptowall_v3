# IDA Pro
Series of IDA-related files that can be used on CryptoWall version 3 samples.

### idb/
A comprehensive IDB file that was used against an unpacked copy of 1dba7c364d043c8e53d39e03af88747dfcf60174fe8a2106d1a8836bd6c745a5.

### ida_python/cryptowall_iat.py
Attempts to build the dynamically generated IAT that is produced by CryptoWall v3 at runtime. Must load necessary enumerations containing hashed function names and library names prior to running.

### ida_python/string_obfuscation_0.py
Code that can be used in IDA when a common string obfuscation technique is used (1/2).

### ida_python/string_obfuscation_1.py
Code that can be used in IDA when a common string obfuscation technique is used (2/2).

### ida_python/decrypt_config.py
Can be run against an unpacked CW3 sample. Attempts to identify and decrypt an embedded blob of data that contains C2 information. 