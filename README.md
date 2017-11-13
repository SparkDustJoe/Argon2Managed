# Argon2Managed
This is a C++/CLR port of Argon2 password hashing algorithm (as of version 0x13)

You can find the original codebase at https://github.com/P-H-C/phc-winner-argon2.

This implementation should be completely compatible with generating and verifying latest version Argon2 hashes.  This is still a rough implementation, so there might be some rough edges.  

Please indicate any issues found, but as for new features, if the original codebase offers a feature that this library doesn't please indicate as such.

New features should be posted to the original linked above, and if approved by them, then referenced here.

This uses C++ with Managed Types (CLR) to allow for use within .NET without the need for the Core libraries.  This is currently blocking code, so thread-heavy implementations should adjust by calling these methods from within worker- or background-threads.

This is released under the Apache 2.0 license and the CC0 license to be compatible with the original.  All code copyrights lay with the original code authors, and numerous adjustments Copyright 2017 Dustin J Sparks to be compatible with the CLR in .NET.
