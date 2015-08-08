
all: intl.dll

intl.dll: win_intl.c win_iconv.c
	$(CC) /Fe$@ /LD /MD /I. $** /link /DEF:intl.def

clean:
	del *.dll *.obj *.exp *.lib

