unit ConsolePasswordReader;

interface

{Reads a password from the console with hidden echo (asterisks displayed instead of characters).
Uses Windows Console API to disable ENABLE_ECHO_INPUT, reads character-by-character.
Returns empty string if user presses Enter without typing, or on console error.}
function ReadPasswordFromConsole(const Prompt: string): string;

implementation

uses
	Windows, SysUtils;

function ReadPasswordFromConsole(const Prompt: string): string;
var
	StdInput: THandle;
	OriginalMode: DWORD;
	ModeChanged: Boolean;
	InputChar: WideChar;
	CharsRead: DWORD;
begin
	Result := '';
	ModeChanged := False;
	StdInput := GetStdHandle(STD_INPUT_HANDLE);
	if StdInput = INVALID_HANDLE_VALUE then
		Exit;

	Write(Prompt);

	if GetConsoleMode(StdInput, OriginalMode) then
	begin
		{Disable echo so typed characters are not displayed}
		SetConsoleMode(StdInput, OriginalMode and (not ENABLE_ECHO_INPUT));
		ModeChanged := True;
	end;

	try
		while True do
		begin
			if not ReadConsoleW(StdInput, @InputChar, 1, CharsRead, nil) then
				Break;
			if CharsRead = 0 then
				Break;

			if (InputChar = #13) or (InputChar = #10) then
				Break;

			if InputChar = #8 then
			begin
				{Backspace: remove last character and erase asterisk from display}
				if Length(Result) > 0 then
				begin
					Delete(Result, Length(Result), 1);
					Write(#8' '#8);
				end;
			end
			else
			begin
				Result := Result + InputChar;
				Write('*');
			end;
		end;
	finally
		if ModeChanged then
			SetConsoleMode(StdInput, OriginalMode);
		Writeln; {Move to next line after password entry}
	end;
end;

end.
