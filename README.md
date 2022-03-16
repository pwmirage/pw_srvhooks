# pw_srvhooks
Perfect World server side modifications (preloaded .so + runtime code patching). This repository contains injectable libraries for pw server executables commonly known as gs and gamedbd (and possibly more in the future).

Here's how it works:

1. LD_PRELOAD a lib into the target pw executable
2. instrument pw code with i386 ASM to call our C functions
3. add new functionality

Not long after this project was started all pw source files in c++ were leaked to the internet, so it might seem reasonable to drop this and just modify/recompile the original binaries. However, messing with foreign, chinese, mmo sprint-ed code doesn't sound like fun. As we're modifying PW strictly for fun (ours and others') this project continues to live and refuses to die.
