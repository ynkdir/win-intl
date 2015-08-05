
all: intl.dll

intl.dll: win_intl.c
	$(CC) /Fe:$@ /LD /MD $** /link /DEF:intl.def

clean:
	del *.dll *.obj *.exp *.lib

