program CloudCryptTest;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
	System.SysUtils,
	DUnitX.Loggers.Console,
	DUnitX.Loggers.Xml.NUnit,
	DUnitX.TestFramework,
	CloudCryptCore in '..\CloudCryptCore.pas',
	Cipher in '..\..\..\src\Infrastructure\Cipher\Cipher.pas',
	CipherProfile in '..\..\..\src\Infrastructure\Cipher\CipherProfile.pas',
	CipherStreams in '..\..\..\src\Infrastructure\Cipher\CipherStreams.pas',
	BlockCipher in '..\..\..\src\Infrastructure\Cipher\BlockCipher.pas',
	OpenSSLCipher in '..\..\..\src\Infrastructure\Cipher\OpenSSLCipher.pas',
	BCryptProvider in '..\..\..\src\Infrastructure\Cipher\BCryptProvider.pas',
	BCryptCipher in '..\..\..\src\Infrastructure\Cipher\BCryptCipher.pas',
	OpenSSLProvider in '..\..\..\src\Infrastructure\OpenSSL\OpenSSLProvider.pas',
	CloudConstants in '..\..\..\src\Domain\Constants\CloudConstants.pas',
	DCPcrypt2 in '..\..\..\src\libs\DCPCrypt\DCPcrypt2.pas',
	DCPblockciphers in '..\..\..\src\libs\DCPCrypt\DCPblockciphers.pas',
	DCPconst in '..\..\..\src\libs\DCPCrypt\DCPconst.pas',
	DCPtypes in '..\..\..\src\libs\DCPCrypt\DCPtypes.pas',
	DCPbase64 in '..\..\..\src\libs\DCPCrypt\DCPbase64.pas',
	DCPrijndael in '..\..\..\src\libs\DCPCrypt\Ciphers\DCPrijndael.pas',
	DCPtwofish in '..\..\..\src\libs\DCPCrypt\Ciphers\DCPtwofish.pas',
	DCPsha1 in '..\..\..\src\libs\DCPCrypt\Hashes\DCPsha1.pas',
	DCPsha256 in '..\..\..\src\libs\DCPCrypt\Hashes\DCPsha256.pas',
	CloudCryptCoreTest in 'CloudCryptCoreTest.pas';

var
	Runner: ITestRunner;
	Results: IRunResults;
	Logger: ITestLogger;
	NUnitLogger: ITestLogger;

begin
	try
		TDUnitX.CheckCommandLine;
		Runner := TDUnitX.CreateRunner;
		Runner.UseRTTI := True;
		Logger := TDUnitXConsoleLogger.Create(True);
		Runner.AddLogger(Logger);
		NUnitLogger := TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
		Runner.AddLogger(NUnitLogger);
		Runner.FailsOnNoAsserts := False;
		Results := Runner.Execute;
		if not Results.AllPassed then
			System.ExitCode := EXIT_ERRORS;
	except
		on E: Exception do
		begin
			System.ExitCode := EXIT_ERRORS;
			Writeln(E.ClassName, ': ', E.Message);
		end;
	end;
end.
