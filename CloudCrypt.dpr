program CloudCrypt;

{$APPTYPE CONSOLE}

uses
	SysUtils,
	System.IOUtils,
	Cipher in '..\..\src\Infrastructure\Cipher\Cipher.pas',
	CipherProfile in '..\..\src\Infrastructure\Cipher\CipherProfile.pas',
	CipherStreams in '..\..\src\Infrastructure\Cipher\CipherStreams.pas',
	BlockCipher in '..\..\src\Infrastructure\Cipher\BlockCipher.pas',
	OpenSSLCipher in '..\..\src\Infrastructure\Cipher\OpenSSLCipher.pas',
	BCryptProvider in '..\..\src\Infrastructure\Cipher\BCryptProvider.pas',
	BCryptCipher in '..\..\src\Infrastructure\Cipher\BCryptCipher.pas',
	OpenSSLProvider in '..\..\src\Infrastructure\OpenSSL\OpenSSLProvider.pas',
	CloudConstants in '..\..\src\Domain\Constants\CloudConstants.pas',
	DCPcrypt2 in '..\..\src\libs\DCPCrypt\DCPcrypt2.pas',
	DCPblockciphers in '..\..\src\libs\DCPCrypt\DCPblockciphers.pas',
	DCPconst in '..\..\src\libs\DCPCrypt\DCPconst.pas',
	DCPtypes in '..\..\src\libs\DCPCrypt\DCPtypes.pas',
	DCPbase64 in '..\..\src\libs\DCPCrypt\DCPbase64.pas',
	DCPrijndael in '..\..\src\libs\DCPCrypt\Ciphers\DCPrijndael.pas',
	DCPtwofish in '..\..\src\libs\DCPCrypt\Ciphers\DCPtwofish.pas',
	DCPsha1 in '..\..\src\libs\DCPCrypt\Hashes\DCPsha1.pas',
	DCPsha256 in '..\..\src\libs\DCPCrypt\Hashes\DCPsha256.pas',
	ConsolePasswordReader in 'ConsolePasswordReader.pas',
	CloudCryptCore in 'CloudCryptCore.pas';

procedure PrintUsage;
begin
	Writeln('CloudCrypt - Standalone encryption tool for CloudMailRu');
	Writeln;
	Writeln('Usage:');
	Writeln('  CloudCrypt encrypt -in <path> -out <path> [-p <password>] [-profile <id>]');
	Writeln('  CloudCrypt decrypt -in <path> -out <path> [-p <password>] [-profile <id>]');
	Writeln('  CloudCrypt profiles');
	Writeln('  CloudCrypt help');
	Writeln;
	Writeln('Options:');
	Writeln('  -in <path>       Input file or directory');
	Writeln('  -out <path>      Output file or directory (must differ from input)');
	Writeln('  -p <password>    Encryption password (prompted interactively if omitted)');
	Writeln('  -profile <id>    Cipher profile ID (use "profiles" command to list)');
	Writeln;
	Writeln('When -in is a directory, -out must be a directory. Files are processed recursively.');
	Writeln('Default profile: dcpcrypt-aes256-cfb8-sha1 (legacy, compatible with most encrypted files).');
	Writeln;
	Writeln('Exit codes:');
	Writeln('  0  Success');
	Writeln('  1  Invalid arguments');
	Writeln('  2  Password not provided');
	Writeln('  3  Unknown cipher profile');
	Writeln('  4  Input path does not exist');
	Writeln('  5  One or more files failed during processing');
end;

procedure PrintProfiles;
var
	Profiles: TArray<TCipherProfile>;
	Profile: TCipherProfile;
	DefaultProfile: TCipherProfile;
begin
	TCipherProfileRegistry.Initialize(
		TOpenSSLProvider.Create('', False),
		TBCryptProvider.Create
	);
	try
		Profiles := TCipherProfileRegistry.GetProfiles;
		DefaultProfile := TCipherProfileRegistry.GetDefaultProfile;

		Writeln('Available cipher profiles:');
		Writeln;
		Writeln(Format('  %-40s %-20s %8s  %s', ['ID', 'Backend', 'Key bits', 'Name']));
		Writeln(StringOfChar('-', 100));

		for Profile in Profiles do
		begin
			if Profile.Id = DefaultProfile.Id then
				Writeln(Format('  %-40s %-20s %8d  %s (default)', [Profile.Id, Profile.BackendName, Profile.KeySizeBits, Profile.DisplayName]))
			else
				Writeln(Format('  %-40s %-20s %8d  %s', [Profile.Id, Profile.BackendName, Profile.KeySizeBits, Profile.DisplayName]));
		end;

		Writeln;
		Writeln(Format('Total: %d profiles', [Length(Profiles)]));
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

function BuildArgsFromCommandLine: TArray<string>;
var
	I: Integer;
begin
	SetLength(Result, ParamCount);
	for I := 1 to ParamCount do
		Result[I - 1] := ParamStr(I);
end;

function RunCryptCommand(const Args: TCommandLineArgs): Integer;
var
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
	Password: string;
	Validation: TValidationResult;
	Processed, Failed: Integer;
	InPathFull, OutPathFull: string;
begin
	Validation := ValidateCryptArgs(Args);
	if Validation.ExitCode <> EXIT_SUCCESS then
	begin
		Writeln(ErrOutput, 'ERROR: ' + Validation.ErrorMessage);
		Exit(Validation.ExitCode);
	end;

	{Get password}
	Password := Args.Password;
	if not Args.HasPassword then
	begin
		Password := ReadPasswordFromConsole('Enter password: ');
		if Password = '' then
		begin
			Writeln(ErrOutput, 'ERROR: Password is required.');
			Exit(EXIT_NO_PASSWORD);
		end;
	end;

	{Initialize cipher registry with all available backends}
	TCipherProfileRegistry.Initialize(
		TOpenSSLProvider.Create('', False),
		TBCryptProvider.Create
	);
	try
		{Resolve profile}
		if Args.ProfileId = '' then
		begin
			Profile := TCipherProfileRegistry.GetDefaultProfile;
			Writeln(Format('Using default profile: %s', [Profile.Id]));
		end
		else
		begin
			if not TCipherProfileRegistry.FindById(Args.ProfileId, Profile) then
			begin
				Writeln(ErrOutput, Format('ERROR: Unknown cipher profile: %s', [Args.ProfileId]));
				Writeln(ErrOutput, 'Run "CloudCrypt profiles" to list available profiles.');
				Exit(EXIT_UNKNOWN_PROFILE);
			end;
			Writeln(Format('Using profile: %s', [Profile.Id]));
		end;

		{Create cipher instance}
		FileCipher := Profile.CreateCipher(Password);

		Processed := 0;
		Failed := 0;

		InPathFull := ExpandFileName(Args.InputPath);
		OutPathFull := ExpandFileName(Args.OutputPath);

		if Args.Command = cmdEncrypt then
			Writeln('Encrypting...')
		else
			Writeln('Decrypting...');

		if TDirectory.Exists(InPathFull) then
			ProcessDirectory(FileCipher, InPathFull, OutPathFull, Args.Command = cmdEncrypt, Processed, Failed)
		else
			ProcessFile(FileCipher, InPathFull, OutPathFull, Args.Command = cmdEncrypt, Processed, Failed);

		Writeln;
		Writeln(Format('Processed: %d files, %d failed', [Processed, Failed]));

		if Failed > 0 then
			Result := EXIT_PROCESSING_ERRORS
		else
			Result := EXIT_SUCCESS;
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

var
	Args: TCommandLineArgs;
	ExitResult: Integer;
begin
	try
		Args := ParseArguments(BuildArgsFromCommandLine);

		case Args.Command of
			cmdHelp:
				begin
					PrintUsage;
					ExitResult := EXIT_INVALID_ARGS;
				end;
			cmdProfiles:
				begin
					PrintProfiles;
					ExitResult := EXIT_INVALID_ARGS;
				end;
			cmdEncrypt, cmdDecrypt:
				ExitResult := RunCryptCommand(Args);
		else
			begin
				Writeln(ErrOutput, Format('ERROR: Unknown command: %s', [ParamStr(1)]));
				Writeln(ErrOutput, 'Run "CloudCrypt help" for usage.');
				ExitResult := EXIT_INVALID_ARGS;
			end;
		end;

		ExitCode := ExitResult;
	except
		on E: Exception do
		begin
			Writeln(ErrOutput, Format('FATAL: %s', [E.Message]));
			ExitCode := EXIT_INVALID_ARGS;
		end;
	end;
end.
