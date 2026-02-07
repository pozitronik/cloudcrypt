unit CloudCryptCore;

interface

uses
	SysUtils, System.IOUtils, Cipher;

const
	EXIT_SUCCESS = 0;
	EXIT_INVALID_ARGS = 1;
	EXIT_NO_PASSWORD = 2;
	EXIT_UNKNOWN_PROFILE = 3;
	EXIT_INPUT_NOT_FOUND = 4;
	EXIT_PROCESSING_ERRORS = 5;

type
	TCommand = (cmdHelp, cmdProfiles, cmdEncrypt, cmdDecrypt, cmdUnknown);

	TCommandLineArgs = record
		Command: TCommand;
		InputPath: string;
		OutputPath: string;
		Password: string;
		ProfileId: string;
		HasPassword: Boolean;
	end;

	{Validation result returned by ValidateCryptArgs before cipher operations begin}
	TValidationResult = record
		ExitCode: Integer;
		ErrorMessage: string;
	end;

{Parses an array of command-line arguments into a structured record.
Accepts Args starting from the command (index 0 = command, not the executable name).}
function ParseArguments(const Args: TArray<string>): TCommandLineArgs;

{Validates arguments for encrypt/decrypt commands.
Returns EXIT_SUCCESS (0) when valid; a non-zero exit code otherwise.
Does NOT check password (that's handled separately by the caller).}
function ValidateCryptArgs(const Args: TCommandLineArgs): TValidationResult;

{Encrypts or decrypts a single file using the provided cipher.
Increments Processed on success, Failed on error. Writes status to stdout/stderr.}
procedure ProcessFile(const FileCipher: IFileCipher; const InFile, OutFile: string; Encrypt: Boolean;
	var Processed, Failed: Integer);

{Recursively encrypts or decrypts all files in InDir, replicating structure under OutDir.}
procedure ProcessDirectory(const FileCipher: IFileCipher; const InDir, OutDir: string; Encrypt: Boolean;
	var Processed, Failed: Integer);

implementation

function ParseArguments(const Args: TArray<string>): TCommandLineArgs;
var
	I: Integer;
	Arg: string;
begin
	Result := Default(TCommandLineArgs);
	Result.Command := cmdUnknown;
	Result.HasPassword := False;

	if Length(Args) = 0 then
	begin
		Result.Command := cmdHelp;
		Exit;
	end;

	Arg := LowerCase(Args[0]);
	if (Arg = 'help') or (Arg = '-h') or (Arg = '--help') or (Arg = '/?') then
		Result.Command := cmdHelp
	else if Arg = 'profiles' then
		Result.Command := cmdProfiles
	else if Arg = 'encrypt' then
		Result.Command := cmdEncrypt
	else if Arg = 'decrypt' then
		Result.Command := cmdDecrypt;

	I := 1;
	while I < Length(Args) do
	begin
		Arg := LowerCase(Args[I]);
		if (Arg = '-in') and (I + 1 < Length(Args)) then
		begin
			Inc(I);
			Result.InputPath := Args[I];
		end
		else if (Arg = '-out') and (I + 1 < Length(Args)) then
		begin
			Inc(I);
			Result.OutputPath := Args[I];
		end
		else if (Arg = '-p') and (I + 1 < Length(Args)) then
		begin
			Inc(I);
			Result.Password := Args[I];
			Result.HasPassword := True;
		end
		else if (Arg = '-profile') and (I + 1 < Length(Args)) then
		begin
			Inc(I);
			Result.ProfileId := Args[I];
		end;
		Inc(I);
	end;
end;

function ValidateCryptArgs(const Args: TCommandLineArgs): TValidationResult;
var
	InPathFull, OutPathFull: string;
begin
	Result.ExitCode := EXIT_SUCCESS;
	Result.ErrorMessage := '';

	if (Args.InputPath = '') or (Args.OutputPath = '') then
	begin
		Result.ExitCode := EXIT_INVALID_ARGS;
		Result.ErrorMessage := 'Both -in and -out are required.';
		Exit;
	end;

	InPathFull := ExpandFileName(Args.InputPath);
	OutPathFull := ExpandFileName(Args.OutputPath);

	if not TFile.Exists(InPathFull) and not TDirectory.Exists(InPathFull) then
	begin
		Result.ExitCode := EXIT_INPUT_NOT_FOUND;
		Result.ErrorMessage := Format('Input path does not exist: %s', [InPathFull]);
		Exit;
	end;

	if SameText(InPathFull, OutPathFull) then
	begin
		Result.ExitCode := EXIT_INVALID_ARGS;
		Result.ErrorMessage := 'Input and output paths must differ (CFB-8 cannot operate in-place).';
		Exit;
	end;

	if TDirectory.Exists(InPathFull) and TFile.Exists(OutPathFull) then
	begin
		Result.ExitCode := EXIT_INVALID_ARGS;
		Result.ErrorMessage := 'When input is a directory, output must be a directory too.';
		Exit;
	end;
end;

procedure ProcessFile(const FileCipher: IFileCipher; const InFile, OutFile: string; Encrypt: Boolean;
	var Processed, Failed: Integer);
var
	CipherResult: Integer;
	FileSize: Int64;
begin
	try
		if Encrypt then
			CipherResult := FileCipher.CryptFile(InFile, OutFile)
		else
			CipherResult := FileCipher.DecryptFile(InFile, OutFile);

		if CipherResult = CIPHER_OK then
		begin
			FileSize := TFile.GetSize(InFile);
			Writeln(Format('  [OK] %s (%d bytes)', [InFile, FileSize]));
			Inc(Processed);
		end
		else
		begin
			Writeln(ErrOutput, Format('  [FAIL] %s: cipher error code %d', [InFile, CipherResult]));
			Inc(Failed);
		end;
	except
		on E: Exception do
		begin
			Writeln(ErrOutput, Format('  [FAIL] %s: %s', [InFile, E.Message]));
			Inc(Failed);
		end;
	end;
end;

procedure ProcessDirectory(const FileCipher: IFileCipher; const InDir, OutDir: string; Encrypt: Boolean;
	var Processed, Failed: Integer);
var
	Files: TArray<string>;
	Dirs: TArray<string>;
	F, SubDir, OutFile, OutSubDir: string;
begin
	ForceDirectories(OutDir);

	Files := TDirectory.GetFiles(InDir);
	for F in Files do
	begin
		OutFile := TPath.Combine(OutDir, TPath.GetFileName(F));
		ProcessFile(FileCipher, F, OutFile, Encrypt, Processed, Failed);
	end;

	Dirs := TDirectory.GetDirectories(InDir);
	for SubDir in Dirs do
	begin
		OutSubDir := TPath.Combine(OutDir, TPath.GetFileName(SubDir));
		ProcessDirectory(FileCipher, SubDir, OutSubDir, Encrypt, Processed, Failed);
	end;
end;

end.
