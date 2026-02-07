unit CloudCryptCoreTest;

interface

uses
	DUnitX.TestFramework, CloudCryptCore, Cipher, CipherProfile, OpenSSLProvider, BCryptProvider;

type

	{Tests for ParseArguments: command-line parsing into TCommandLineArgs}
	[TestFixture]
	TParseArgumentsTest = class
	public
		[Test]
		procedure EmptyArgs_DefaultsToHelp;
		[Test]
		procedure ParsesEncryptCommand;
		[Test]
		procedure ParsesDecryptCommand;
		[Test]
		procedure ParsesHelpCommand;
		[Test]
		procedure ParsesProfilesCommand;
		[Test]
		procedure ParsesHFlag;
		[Test]
		procedure ParsesDoubleHyphenHelp;
		[Test]
		procedure ParsesSlashQuestionMark;
		[Test]
		procedure UnknownCommand_ReturnsUnknown;
		[Test]
		procedure ParsesInputPath;
		[Test]
		procedure ParsesOutputPath;
		[Test]
		procedure ParsesPassword;
		[Test]
		procedure PasswordSetsHasPasswordFlag;
		[Test]
		procedure NoPassword_HasPasswordIsFalse;
		[Test]
		procedure ParsesProfileId;
		[Test]
		procedure ParsesAllArgumentsTogether;
		[Test]
		procedure CommandIsCaseInsensitive;
		[Test]
		procedure FlagsAreCaseInsensitive;
		[Test]
		procedure MissingValueAfterInFlag_IgnoresIt;
		[Test]
		procedure MissingValueAfterOutFlag_IgnoresIt;
		[Test]
		procedure MissingValueAfterPasswordFlag_IgnoresIt;
		[Test]
		procedure MissingValueAfterProfileFlag_IgnoresIt;
		[Test]
		procedure UnknownFlagsAreIgnored;
		[Test]
		procedure PathsPreserveOriginalCase;
		[Test]
		procedure EmptyPasswordString_SetsHasPassword;
	end;

	{Tests for ValidateCryptArgs: argument validation before cipher operations}
	[TestFixture]
	TValidateCryptArgsTest = class
	private
		FTempDir: string;
		FTestFile: string;
	public
		[Setup]
		procedure Setup;
		[Teardown]
		procedure Teardown;
		[Test]
		procedure EmptyInputPath_ReturnsInvalidArgs;
		[Test]
		procedure EmptyOutputPath_ReturnsInvalidArgs;
		[Test]
		procedure BothPathsEmpty_ReturnsInvalidArgs;
		[Test]
		procedure NonExistentInput_ReturnsInputNotFound;
		[Test]
		procedure ValidFilePaths_ReturnsSuccess;
		[Test]
		procedure ValidDirectoryInput_ReturnsSuccess;
		[Test]
		procedure SameInputAndOutput_ReturnsInvalidArgs;
		[Test]
		procedure SamePathDifferentCase_ReturnsInvalidArgs;
		[Test]
		procedure DirectoryInputWithFileOutput_ReturnsInvalidArgs;
		[Test]
		procedure ErrorMessageIsNotEmpty_OnFailure;
		[Test]
		procedure ErrorMessageIsEmpty_OnSuccess;
	end;

	{Tests for ProcessFile: single-file encryption/decryption and counter tracking}
	[TestFixture]
	TProcessFileTest = class
	private
		FTempDir: string;
		procedure CreateTestFile(const FileName, Content: string);
		function ReadFileContent(const FileName: string): string;
	public
		[Setup]
		procedure Setup;
		[Teardown]
		procedure Teardown;
		[Test]
		procedure EncryptFile_IncrementsProcessed;
		[Test]
		procedure DecryptFile_IncrementsProcessed;
		[Test]
		procedure EncryptDecryptRoundtrip_PreservesContent;
		[Test]
		procedure EncryptedFile_DiffersFromOriginal;
		[Test]
		procedure EncryptedFile_SameSizeAsOriginal;
		[Test]
		procedure NonExistentSource_IncrementsFailed;
		[Test]
		procedure ProcessedAndFailed_AccumulateAcrossCalls;
	end;

	{Tests for ProcessDirectory: recursive directory encryption/decryption}
	[TestFixture]
	TProcessDirectoryTest = class
	private
		FTempDir: string;
		procedure CreateTestFile(const RelativePath, Content: string);
	public
		[Setup]
		procedure Setup;
		[Teardown]
		procedure Teardown;
		[Test]
		procedure ProcessesAllFilesInDirectory;
		[Test]
		procedure CreatesOutputDirectoryStructure;
		[Test]
		procedure ProcessesNestedSubdirectories;
		[Test]
		procedure EmptyDirectory_ProcessesZeroFiles;
		[Test]
		procedure DirectoryRoundtrip_PreservesAllContent;
	end;

	{Tests for cipher profile resolution and cross-profile roundtrip}
	[TestFixture]
	TProfileRoundtripTest = class
	private
		FTempDir: string;
		procedure CreateTestFile(const FileName, Content: string);
		function ReadFileContent(const FileName: string): string;
	public
		[Setup]
		procedure Setup;
		[Teardown]
		procedure Teardown;
		[Test]
		procedure DefaultProfile_IsLegacyAES;
		[Test]
		procedure FindValidProfile_ReturnsTrue;
		[Test]
		procedure FindInvalidProfile_ReturnsFalse;
		[Test]
		procedure AllProfiles_CreateValidCiphers;
		[Test]
		procedure DCPCryptAES_Roundtrip;
		[Test]
		procedure DCPCryptAES256SHA256_Roundtrip;
		[Test]
		procedure DCPCryptTwofish_Roundtrip;
		[Test]
		procedure BCrypt_Roundtrip;
		[Test]
		procedure WrongPassword_ProducesGarbage;
		[Test]
		procedure DifferentProfiles_ProduceDifferentCiphertext;
	end;

implementation

uses
	Windows, SysUtils, Classes, System.IOUtils;

{ TParseArgumentsTest }

procedure TParseArgumentsTest.EmptyArgs_DefaultsToHelp;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments([]);
	Assert.AreEqual(Ord(cmdHelp), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesEncryptCommand;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt']);
	Assert.AreEqual(Ord(cmdEncrypt), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesDecryptCommand;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['decrypt']);
	Assert.AreEqual(Ord(cmdDecrypt), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesHelpCommand;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['help']);
	Assert.AreEqual(Ord(cmdHelp), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesProfilesCommand;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['profiles']);
	Assert.AreEqual(Ord(cmdProfiles), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesHFlag;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['-h']);
	Assert.AreEqual(Ord(cmdHelp), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesDoubleHyphenHelp;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['--help']);
	Assert.AreEqual(Ord(cmdHelp), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesSlashQuestionMark;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['/?']);
	Assert.AreEqual(Ord(cmdHelp), Ord(Args.Command));
end;

procedure TParseArgumentsTest.UnknownCommand_ReturnsUnknown;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['foobar']);
	Assert.AreEqual(Ord(cmdUnknown), Ord(Args.Command));
end;

procedure TParseArgumentsTest.ParsesInputPath;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-in', 'C:\input.txt']);
	Assert.AreEqual('C:\input.txt', Args.InputPath);
end;

procedure TParseArgumentsTest.ParsesOutputPath;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-out', 'C:\output.txt']);
	Assert.AreEqual('C:\output.txt', Args.OutputPath);
end;

procedure TParseArgumentsTest.ParsesPassword;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-p', 'secret123']);
	Assert.AreEqual('secret123', Args.Password);
end;

procedure TParseArgumentsTest.PasswordSetsHasPasswordFlag;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-p', 'secret']);
	Assert.IsTrue(Args.HasPassword);
end;

procedure TParseArgumentsTest.NoPassword_HasPasswordIsFalse;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-in', 'a.txt', '-out', 'b.txt']);
	Assert.IsFalse(Args.HasPassword);
end;

procedure TParseArgumentsTest.ParsesProfileId;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-profile', 'bcrypt-aes256-cfb8-pbkdf2']);
	Assert.AreEqual('bcrypt-aes256-cfb8-pbkdf2', Args.ProfileId);
end;

procedure TParseArgumentsTest.ParsesAllArgumentsTogether;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['decrypt', '-in', 'input.enc', '-out', 'output.txt', '-p', 'pass', '-profile', 'some-profile']);
	Assert.AreEqual(Ord(cmdDecrypt), Ord(Args.Command));
	Assert.AreEqual('input.enc', Args.InputPath);
	Assert.AreEqual('output.txt', Args.OutputPath);
	Assert.AreEqual('pass', Args.Password);
	Assert.AreEqual('some-profile', Args.ProfileId);
	Assert.IsTrue(Args.HasPassword);
end;

procedure TParseArgumentsTest.CommandIsCaseInsensitive;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['ENCRYPT']);
	Assert.AreEqual(Ord(cmdEncrypt), Ord(Args.Command));

	Args := ParseArguments(['Decrypt']);
	Assert.AreEqual(Ord(cmdDecrypt), Ord(Args.Command));

	Args := ParseArguments(['PROFILES']);
	Assert.AreEqual(Ord(cmdProfiles), Ord(Args.Command));
end;

procedure TParseArgumentsTest.FlagsAreCaseInsensitive;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-IN', 'a.txt', '-OUT', 'b.txt', '-P', 'pass']);
	Assert.AreEqual('a.txt', Args.InputPath);
	Assert.AreEqual('b.txt', Args.OutputPath);
	Assert.AreEqual('pass', Args.Password);
end;

procedure TParseArgumentsTest.MissingValueAfterInFlag_IgnoresIt;
var
	Args: TCommandLineArgs;
begin
	{-in is the last arg with no value following it}
	Args := ParseArguments(['encrypt', '-in']);
	Assert.AreEqual('', Args.InputPath);
end;

procedure TParseArgumentsTest.MissingValueAfterOutFlag_IgnoresIt;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-out']);
	Assert.AreEqual('', Args.OutputPath);
end;

procedure TParseArgumentsTest.MissingValueAfterPasswordFlag_IgnoresIt;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-p']);
	Assert.AreEqual('', Args.Password);
	Assert.IsFalse(Args.HasPassword);
end;

procedure TParseArgumentsTest.MissingValueAfterProfileFlag_IgnoresIt;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-profile']);
	Assert.AreEqual('', Args.ProfileId);
end;

procedure TParseArgumentsTest.UnknownFlagsAreIgnored;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-unknown', 'value', '-in', 'a.txt']);
	Assert.AreEqual('a.txt', Args.InputPath);
	Assert.AreEqual(Ord(cmdEncrypt), Ord(Args.Command));
end;

procedure TParseArgumentsTest.PathsPreserveOriginalCase;
var
	Args: TCommandLineArgs;
begin
	Args := ParseArguments(['encrypt', '-in', 'C:\MyFolder\File.TXT', '-out', 'D:\Other\Output.ENC']);
	Assert.AreEqual('C:\MyFolder\File.TXT', Args.InputPath);
	Assert.AreEqual('D:\Other\Output.ENC', Args.OutputPath);
end;

procedure TParseArgumentsTest.EmptyPasswordString_SetsHasPassword;
var
	Args: TCommandLineArgs;
begin
	{-p followed by empty string: HasPassword is true, password is empty.
	This can happen when invoked as: CloudCrypt encrypt -p "" -in a -out b}
	Args := ParseArguments(['encrypt', '-p', '']);
	Assert.IsTrue(Args.HasPassword);
	Assert.AreEqual('', Args.Password);
end;

{ TValidateCryptArgsTest }

procedure TValidateCryptArgsTest.Setup;
begin
	FTempDir := TPath.Combine(TPath.GetTempPath, 'CloudCryptTest_' + IntToStr(GetCurrentThreadId));
	ForceDirectories(FTempDir);
	FTestFile := TPath.Combine(FTempDir, 'existing.txt');
	TFile.WriteAllText(FTestFile, 'test content');
end;

procedure TValidateCryptArgsTest.Teardown;
begin
	if TDirectory.Exists(FTempDir) then
		TDirectory.Delete(FTempDir, True);
end;

procedure TValidateCryptArgsTest.EmptyInputPath_ReturnsInvalidArgs;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.OutputPath := 'some_output.txt';
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INVALID_ARGS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.EmptyOutputPath_ReturnsInvalidArgs;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTestFile;
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INVALID_ARGS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.BothPathsEmpty_ReturnsInvalidArgs;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INVALID_ARGS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.NonExistentInput_ReturnsInputNotFound;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := TPath.Combine(FTempDir, 'nonexistent.txt');
	Args.OutputPath := TPath.Combine(FTempDir, 'output.txt');
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INPUT_NOT_FOUND, R.ExitCode);
end;

procedure TValidateCryptArgsTest.ValidFilePaths_ReturnsSuccess;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTestFile;
	Args.OutputPath := TPath.Combine(FTempDir, 'output.txt');
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_SUCCESS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.ValidDirectoryInput_ReturnsSuccess;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTempDir;
	Args.OutputPath := FTempDir + '_out';
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_SUCCESS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.SameInputAndOutput_ReturnsInvalidArgs;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTestFile;
	Args.OutputPath := FTestFile;
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INVALID_ARGS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.SamePathDifferentCase_ReturnsInvalidArgs;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTestFile;
	Args.OutputPath := UpperCase(FTestFile);
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INVALID_ARGS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.DirectoryInputWithFileOutput_ReturnsInvalidArgs;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTempDir;
	Args.OutputPath := FTestFile;
	R := ValidateCryptArgs(Args);
	Assert.AreEqual(EXIT_INVALID_ARGS, R.ExitCode);
end;

procedure TValidateCryptArgsTest.ErrorMessageIsNotEmpty_OnFailure;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	R := ValidateCryptArgs(Args);
	Assert.IsNotEmpty(R.ErrorMessage);
end;

procedure TValidateCryptArgsTest.ErrorMessageIsEmpty_OnSuccess;
var
	Args: TCommandLineArgs;
	R: TValidationResult;
begin
	Args := Default(TCommandLineArgs);
	Args.InputPath := FTestFile;
	Args.OutputPath := TPath.Combine(FTempDir, 'output.txt');
	R := ValidateCryptArgs(Args);
	Assert.IsEmpty(R.ErrorMessage);
end;

{ TProcessFileTest }

procedure TProcessFileTest.Setup;
begin
	FTempDir := TPath.Combine(TPath.GetTempPath, 'CloudCryptFileTest_' + IntToStr(GetCurrentThreadId));
	ForceDirectories(FTempDir);
end;

procedure TProcessFileTest.Teardown;
begin
	if TDirectory.Exists(FTempDir) then
		TDirectory.Delete(FTempDir, True);
end;

procedure TProcessFileTest.CreateTestFile(const FileName, Content: string);
begin
	TFile.WriteAllText(TPath.Combine(FTempDir, FileName), Content);
end;

function TProcessFileTest.ReadFileContent(const FileName: string): string;
begin
	Result := TFile.ReadAllText(TPath.Combine(FTempDir, FileName));
end;

procedure TProcessFileTest.EncryptFile_IncrementsProcessed;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
begin
	CreateTestFile('input.txt', 'Hello, World!');
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('testpass');
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'input.txt'),
			TPath.Combine(FTempDir, 'output.enc'),
			True, Processed, Failed);
		Assert.AreEqual(1, Processed);
		Assert.AreEqual(0, Failed);
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessFileTest.DecryptFile_IncrementsProcessed;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
begin
	CreateTestFile('input.txt', 'Hello, World!');
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('testpass');
		{Encrypt first}
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'input.txt'),
			TPath.Combine(FTempDir, 'encrypted.enc'),
			True, Processed, Failed);
		{Decrypt}
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('testpass');
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'encrypted.enc'),
			TPath.Combine(FTempDir, 'decrypted.txt'),
			False, Processed, Failed);
		Assert.AreEqual(1, Processed);
		Assert.AreEqual(0, Failed);
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessFileTest.EncryptDecryptRoundtrip_PreservesContent;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Original, Decrypted: string;
begin
	Original := 'The quick brown fox jumps over the lazy dog. 1234567890!@#$%';
	CreateTestFile('original.txt', Original);
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('roundtrip_pass');
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'original.txt'),
			TPath.Combine(FTempDir, 'encrypted.enc'),
			True, Processed, Failed);

		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('roundtrip_pass');
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'encrypted.enc'),
			TPath.Combine(FTempDir, 'decrypted.txt'),
			False, Processed, Failed);

		Decrypted := ReadFileContent('decrypted.txt');
		Assert.AreEqual(Original, Decrypted);
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessFileTest.EncryptedFile_DiffersFromOriginal;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	OriginalBytes, EncryptedBytes: TBytes;
	I: Integer;
	AllSame: Boolean;
begin
	CreateTestFile('input.txt', 'Some plaintext content that should be encrypted');
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('diffpass');
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'input.txt'),
			TPath.Combine(FTempDir, 'encrypted.enc'),
			True, Processed, Failed);

		OriginalBytes := TFile.ReadAllBytes(TPath.Combine(FTempDir, 'input.txt'));
		EncryptedBytes := TFile.ReadAllBytes(TPath.Combine(FTempDir, 'encrypted.enc'));

		Assert.AreEqual(Length(OriginalBytes), Length(EncryptedBytes));
		AllSame := True;
		for I := 0 to Length(OriginalBytes) - 1 do
			if OriginalBytes[I] <> EncryptedBytes[I] then
			begin
				AllSame := False;
				Break;
			end;
		Assert.IsFalse(AllSame, 'Encrypted content must differ from original');
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessFileTest.EncryptedFile_SameSizeAsOriginal;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	OriginalSize, EncryptedSize: Int64;
begin
	{CFB-8 preserves file size -- no padding, no headers}
	CreateTestFile('input.txt', 'CFB-8 preserves file size exactly');
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('sizetest');
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'input.txt'),
			TPath.Combine(FTempDir, 'encrypted.enc'),
			True, Processed, Failed);

		OriginalSize := TFile.GetSize(TPath.Combine(FTempDir, 'input.txt'));
		EncryptedSize := TFile.GetSize(TPath.Combine(FTempDir, 'encrypted.enc'));
		Assert.AreEqual(OriginalSize, EncryptedSize, 'CFB-8 encrypted file must have same size as original');
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessFileTest.NonExistentSource_IncrementsFailed;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
begin
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('pass');
		Processed := 0;
		Failed := 0;
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'does_not_exist.txt'),
			TPath.Combine(FTempDir, 'output.enc'),
			True, Processed, Failed);
		Assert.AreEqual(0, Processed);
		Assert.AreEqual(1, Failed);
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessFileTest.ProcessedAndFailed_AccumulateAcrossCalls;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
begin
	CreateTestFile('file1.txt', 'content1');
	CreateTestFile('file2.txt', 'content2');
	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('pass');
		Processed := 0;
		Failed := 0;
		{Two successful files}
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'file1.txt'),
			TPath.Combine(FTempDir, 'file1.enc'),
			True, Processed, Failed);
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('pass');
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'file2.txt'),
			TPath.Combine(FTempDir, 'file2.enc'),
			True, Processed, Failed);
		{One failed file}
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('pass');
		ProcessFile(FileCipher,
			TPath.Combine(FTempDir, 'missing.txt'),
			TPath.Combine(FTempDir, 'missing.enc'),
			True, Processed, Failed);
		Assert.AreEqual(2, Processed);
		Assert.AreEqual(1, Failed);
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

{ TProcessDirectoryTest }

procedure TProcessDirectoryTest.Setup;
begin
	FTempDir := TPath.Combine(TPath.GetTempPath, 'CloudCryptDirTest_' + IntToStr(GetCurrentThreadId));
	ForceDirectories(FTempDir);
end;

procedure TProcessDirectoryTest.Teardown;
begin
	if TDirectory.Exists(FTempDir) then
		TDirectory.Delete(FTempDir, True);
end;

procedure TProcessDirectoryTest.CreateTestFile(const RelativePath, Content: string);
var
	FullPath: string;
begin
	FullPath := TPath.Combine(FTempDir, RelativePath);
	ForceDirectories(ExtractFilePath(FullPath));
	TFile.WriteAllText(FullPath, Content);
end;

procedure TProcessDirectoryTest.ProcessesAllFilesInDirectory;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	InDir, OutDir: string;
begin
	InDir := TPath.Combine(FTempDir, 'input');
	OutDir := TPath.Combine(FTempDir, 'output');
	CreateTestFile('input\file1.txt', 'content1');
	CreateTestFile('input\file2.txt', 'content2');
	CreateTestFile('input\file3.txt', 'content3');

	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('dirpass');
		Processed := 0;
		Failed := 0;
		ProcessDirectory(FileCipher, InDir, OutDir, True, Processed, Failed);
		Assert.AreEqual(3, Processed);
		Assert.AreEqual(0, Failed);
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessDirectoryTest.CreatesOutputDirectoryStructure;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	InDir, OutDir: string;
begin
	InDir := TPath.Combine(FTempDir, 'input');
	OutDir := TPath.Combine(FTempDir, 'output');
	CreateTestFile('input\sub1\file.txt', 'content');
	CreateTestFile('input\sub2\file.txt', 'content');

	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('dirpass');
		Processed := 0;
		Failed := 0;
		ProcessDirectory(FileCipher, InDir, OutDir, True, Processed, Failed);
		Assert.IsTrue(TDirectory.Exists(TPath.Combine(OutDir, 'sub1')), 'sub1 directory must be created');
		Assert.IsTrue(TDirectory.Exists(TPath.Combine(OutDir, 'sub2')), 'sub2 directory must be created');
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessDirectoryTest.ProcessesNestedSubdirectories;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	InDir, OutDir: string;
begin
	InDir := TPath.Combine(FTempDir, 'input');
	OutDir := TPath.Combine(FTempDir, 'output');
	CreateTestFile('input\a.txt', 'root file');
	CreateTestFile('input\level1\b.txt', 'level 1 file');
	CreateTestFile('input\level1\level2\c.txt', 'level 2 file');

	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('nestpass');
		Processed := 0;
		Failed := 0;
		ProcessDirectory(FileCipher, InDir, OutDir, True, Processed, Failed);
		Assert.AreEqual(3, Processed);
		Assert.IsTrue(TFile.Exists(TPath.Combine(OutDir, 'a.txt')));
		Assert.IsTrue(TFile.Exists(TPath.Combine(OutDir, 'level1\b.txt')));
		Assert.IsTrue(TFile.Exists(TPath.Combine(OutDir, 'level1\level2\c.txt')));
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessDirectoryTest.EmptyDirectory_ProcessesZeroFiles;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	InDir, OutDir: string;
begin
	InDir := TPath.Combine(FTempDir, 'empty_input');
	OutDir := TPath.Combine(FTempDir, 'empty_output');
	ForceDirectories(InDir);

	TCipherProfileRegistry.Initialize;
	try
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('pass');
		Processed := 0;
		Failed := 0;
		ProcessDirectory(FileCipher, InDir, OutDir, True, Processed, Failed);
		Assert.AreEqual(0, Processed);
		Assert.AreEqual(0, Failed);
		Assert.IsTrue(TDirectory.Exists(OutDir), 'Output directory must be created even if empty');
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

procedure TProcessDirectoryTest.DirectoryRoundtrip_PreservesAllContent;
var
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	InDir, EncDir, DecDir: string;
	OrigContent1, OrigContent2, DecContent1, DecContent2: string;
begin
	InDir := TPath.Combine(FTempDir, 'input');
	EncDir := TPath.Combine(FTempDir, 'encrypted');
	DecDir := TPath.Combine(FTempDir, 'decrypted');

	OrigContent1 := 'First file content with special chars: !@#$%^&*()';
	OrigContent2 := 'Second file in nested directory';
	CreateTestFile('input\file1.txt', OrigContent1);
	CreateTestFile('input\sub\file2.txt', OrigContent2);

	TCipherProfileRegistry.Initialize;
	try
		{Encrypt}
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('roundtrip');
		Processed := 0;
		Failed := 0;
		ProcessDirectory(FileCipher, InDir, EncDir, True, Processed, Failed);
		Assert.AreEqual(2, Processed);

		{Decrypt}
		FileCipher := TCipherProfileRegistry.GetDefaultProfile.CreateCipher('roundtrip');
		Processed := 0;
		Failed := 0;
		ProcessDirectory(FileCipher, EncDir, DecDir, False, Processed, Failed);
		Assert.AreEqual(2, Processed);

		DecContent1 := TFile.ReadAllText(TPath.Combine(DecDir, 'file1.txt'));
		DecContent2 := TFile.ReadAllText(TPath.Combine(DecDir, 'sub\file2.txt'));
		Assert.AreEqual(OrigContent1, DecContent1, 'file1.txt content mismatch after roundtrip');
		Assert.AreEqual(OrigContent2, DecContent2, 'sub\file2.txt content mismatch after roundtrip');
	finally
		TCipherProfileRegistry.Reset;
	end;
end;

{ TProfileRoundtripTest }

procedure TProfileRoundtripTest.Setup;
begin
	FTempDir := TPath.Combine(TPath.GetTempPath, 'CloudCryptProfileTest_' + IntToStr(GetCurrentThreadId));
	ForceDirectories(FTempDir);
	TCipherProfileRegistry.Initialize(
		TOpenSSLProvider.Create('', False),
		TBCryptProvider.Create
	);
end;

procedure TProfileRoundtripTest.Teardown;
begin
	TCipherProfileRegistry.Reset;
	if TDirectory.Exists(FTempDir) then
		TDirectory.Delete(FTempDir, True);
end;

procedure TProfileRoundtripTest.CreateTestFile(const FileName, Content: string);
begin
	TFile.WriteAllText(TPath.Combine(FTempDir, FileName), Content);
end;

function TProfileRoundtripTest.ReadFileContent(const FileName: string): string;
begin
	Result := TFile.ReadAllText(TPath.Combine(FTempDir, FileName));
end;

procedure TProfileRoundtripTest.DefaultProfile_IsLegacyAES;
var
	Profile: TCipherProfile;
begin
	Profile := TCipherProfileRegistry.GetDefaultProfile;
	Assert.AreEqual('dcpcrypt-aes256-cfb8-sha1', string(Profile.Id));
end;

procedure TProfileRoundtripTest.FindValidProfile_ReturnsTrue;
var
	Profile: TCipherProfile;
begin
	Assert.IsTrue(TCipherProfileRegistry.FindById('dcpcrypt-aes256-cfb8-sha256', Profile));
	Assert.AreEqual('dcpcrypt-aes256-cfb8-sha256', string(Profile.Id));
end;

procedure TProfileRoundtripTest.FindInvalidProfile_ReturnsFalse;
var
	Profile: TCipherProfile;
begin
	Assert.IsFalse(TCipherProfileRegistry.FindById('nonexistent-profile', Profile));
end;

procedure TProfileRoundtripTest.AllProfiles_CreateValidCiphers;
var
	Profiles: TArray<TCipherProfile>;
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
begin
	Profiles := TCipherProfileRegistry.GetProfiles;
	Assert.IsTrue(Length(Profiles) >= 3, 'At least 3 DCPCrypt profiles expected');
	for Profile in Profiles do
	begin
		FileCipher := Profile.CreateCipher('test_password');
		Assert.IsNotNull(FileCipher, Format('Profile %s must create a valid cipher', [string(Profile.Id)]));
	end;
end;

procedure TProfileRoundtripTest.DCPCryptAES_Roundtrip;
var
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Original: string;
begin
	Original := 'DCPCrypt AES-256 roundtrip test content';
	CreateTestFile('input.txt', Original);
	TCipherProfileRegistry.FindById('dcpcrypt-aes256-cfb8-sha1', Profile);

	FileCipher := Profile.CreateCipher('aes_test');
	Processed := 0;
	Failed := 0;
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'encrypted.enc'),
		True, Processed, Failed);

	FileCipher := Profile.CreateCipher('aes_test');
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'encrypted.enc'),
		TPath.Combine(FTempDir, 'decrypted.txt'),
		False, Processed, Failed);

	Assert.AreEqual(Original, ReadFileContent('decrypted.txt'));
end;

procedure TProfileRoundtripTest.DCPCryptAES256SHA256_Roundtrip;
var
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Original: string;
begin
	Original := 'DCPCrypt AES-256 SHA-256 KDF roundtrip test';
	CreateTestFile('input.txt', Original);
	TCipherProfileRegistry.FindById('dcpcrypt-aes256-cfb8-sha256', Profile);

	FileCipher := Profile.CreateCipher('sha256_test');
	Processed := 0;
	Failed := 0;
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'encrypted.enc'),
		True, Processed, Failed);

	FileCipher := Profile.CreateCipher('sha256_test');
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'encrypted.enc'),
		TPath.Combine(FTempDir, 'decrypted.txt'),
		False, Processed, Failed);

	Assert.AreEqual(Original, ReadFileContent('decrypted.txt'));
end;

procedure TProfileRoundtripTest.DCPCryptTwofish_Roundtrip;
var
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Original: string;
begin
	Original := 'Twofish-256 roundtrip test content';
	CreateTestFile('input.txt', Original);
	TCipherProfileRegistry.FindById('dcpcrypt-twofish256-cfb8-sha256', Profile);

	FileCipher := Profile.CreateCipher('twofish_test');
	Processed := 0;
	Failed := 0;
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'encrypted.enc'),
		True, Processed, Failed);

	FileCipher := Profile.CreateCipher('twofish_test');
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'encrypted.enc'),
		TPath.Combine(FTempDir, 'decrypted.txt'),
		False, Processed, Failed);

	Assert.AreEqual(Original, ReadFileContent('decrypted.txt'));
end;

procedure TProfileRoundtripTest.BCrypt_Roundtrip;
var
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Original: string;
begin
	Original := 'BCrypt AES-256 PBKDF2 roundtrip test';
	CreateTestFile('input.txt', Original);
	if not TCipherProfileRegistry.FindById('bcrypt-aes256-cfb8-pbkdf2', Profile) then
	begin
		Assert.Pass('BCrypt profile not available, skipping');
		Exit;
	end;

	FileCipher := Profile.CreateCipher('bcrypt_test');
	Processed := 0;
	Failed := 0;
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'encrypted.enc'),
		True, Processed, Failed);

	FileCipher := Profile.CreateCipher('bcrypt_test');
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'encrypted.enc'),
		TPath.Combine(FTempDir, 'decrypted.txt'),
		False, Processed, Failed);

	Assert.AreEqual(Original, ReadFileContent('decrypted.txt'));
end;

procedure TProfileRoundtripTest.WrongPassword_ProducesGarbage;
var
	Profile: TCipherProfile;
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Original, Decrypted: string;
begin
	Original := 'This content will be mangled by wrong password';
	CreateTestFile('input.txt', Original);
	Profile := TCipherProfileRegistry.GetDefaultProfile;

	FileCipher := Profile.CreateCipher('correct_password');
	Processed := 0;
	Failed := 0;
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'encrypted.enc'),
		True, Processed, Failed);

	{Decrypt with wrong password -- CFB-8 silently produces garbage}
	FileCipher := Profile.CreateCipher('wrong_password');
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'encrypted.enc'),
		TPath.Combine(FTempDir, 'decrypted.txt'),
		False, Processed, Failed);

	Decrypted := ReadFileContent('decrypted.txt');
	Assert.AreNotEqual(Original, Decrypted, 'Wrong password must produce different output');
end;

procedure TProfileRoundtripTest.DifferentProfiles_ProduceDifferentCiphertext;
var
	Profile1, Profile2: TCipherProfile;
	FileCipher: IFileCipher;
	Processed, Failed: Integer;
	Enc1Bytes, Enc2Bytes: TBytes;
	I: Integer;
	AllSame: Boolean;
begin
	CreateTestFile('input.txt', 'Same content encrypted with different profiles');

	TCipherProfileRegistry.FindById('dcpcrypt-aes256-cfb8-sha1', Profile1);
	TCipherProfileRegistry.FindById('dcpcrypt-aes256-cfb8-sha256', Profile2);

	FileCipher := Profile1.CreateCipher('same_password');
	Processed := 0;
	Failed := 0;
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'enc1.bin'),
		True, Processed, Failed);

	FileCipher := Profile2.CreateCipher('same_password');
	ProcessFile(FileCipher,
		TPath.Combine(FTempDir, 'input.txt'),
		TPath.Combine(FTempDir, 'enc2.bin'),
		True, Processed, Failed);

	Enc1Bytes := TFile.ReadAllBytes(TPath.Combine(FTempDir, 'enc1.bin'));
	Enc2Bytes := TFile.ReadAllBytes(TPath.Combine(FTempDir, 'enc2.bin'));

	{Different KDFs (SHA-1 vs SHA-256) must produce different ciphertext.
	Compare raw bytes to avoid UTF-8 encoding issues with binary data.}
	Assert.AreEqual(Length(Enc1Bytes), Length(Enc2Bytes), 'Both ciphertexts must have same length');
	AllSame := True;
	for I := 0 to Length(Enc1Bytes) - 1 do
		if Enc1Bytes[I] <> Enc2Bytes[I] then
		begin
			AllSame := False;
			Break;
		end;
	Assert.IsFalse(AllSame, 'Different profiles must produce different ciphertext');
end;

initialization
	TDUnitX.RegisterTestFixture(TParseArgumentsTest);
	TDUnitX.RegisterTestFixture(TValidateCryptArgsTest);
	TDUnitX.RegisterTestFixture(TProcessFileTest);
	TDUnitX.RegisterTestFixture(TProcessDirectoryTest);
	TDUnitX.RegisterTestFixture(TProfileRoundtripTest);

end.
