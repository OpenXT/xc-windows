TARGETTYPE=DRIVER

TARGETLIBS=                              \
        $(DDK_LIB_PATH)\displib.lib      \
        $(DDK_LIB_PATH)\ntoskrnl.lib     \
        $(DDK_LIB_PATH)\hal.lib          \

INCLUDES=                                \
        $(DDK_INC_PATH);                 \
        $(SDK_INC_PATH);                 \
		..\..\shared;					 \
		..\..\inc;						 \
		..\inc;						     \
		..\shared;
		

SOURCES=                                 \
        ..\BDD.cxx                       \
        ..\BDD_DDI.cxx                   \
        ..\BDD_DMM.cxx                   \
        ..\memory.cxx                    \
        ..\BltFuncs.cxx                  \
        ..\BDD_Util.cxx                  \

#MSC_WARNING_LEVEL=$(MSC_WARNING_LEVEL) /W4