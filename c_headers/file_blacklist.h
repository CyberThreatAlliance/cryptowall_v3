// This C header contains a list of blacklisted filenames. CryptoWall version 3
// will ignore any of the files located in this enumeration. The filenames are
// represented by their CRC32 hash. 

enum file_blacklist {
	bl_file_help_decrypt_html = 0xba069e4c,
	bl_file_help_decrypt_png = 0x9b0fd8b3,
	bl_file_help_decrypt_txt = 0x4208466,
	bl_file_help_decrypt_url = 0xec619e8d,
	bl_file_iconcache_db = 0x7bd40679,
	bl_file_thumbs_db = 0x48f43013
};