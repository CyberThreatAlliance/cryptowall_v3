// This C header file contains a list of CRC32-hashed folder names that are 
// blacklisted by the CryptoWall version 3 malware family.

enum folder_blacklist {
	bl_user_account_pictures = 0x78B7E09,
	bl_temp = 0x0B5385CA,
	bl_dot = 0xED4E242,
	bl_inetcache  = 0x1DF021B7,
	bl_program_files_x86_ = 0x224CD3A8,
	bl_sample_music = 0x3FF79651,
	bl_cache = 0x41476BE7,
	bl_program_files = 0x62288CBB,
	bl_nvidia = 0x72D480B3,
	bl_dot_dot = 0x9608161C,
	bl_packages = 0x9BB5C0A7,
	bl_sample_videos = 0xA33D086A,
	bl_default_pictures = 0xA622138A,
	bl_sample_pictures = 0xB91A5F78,
	bl_webcache = 0xD8601609,
	bl_windows = 0xE3E7859B,
	bl_temporary_internet_files = 0xF5832EB4,
	bl_games = 0xFF232B31
};