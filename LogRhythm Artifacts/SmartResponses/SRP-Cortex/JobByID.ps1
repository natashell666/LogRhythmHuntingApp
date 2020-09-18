# Requires -Version 3.0
#
# This Script is used to fetch the observable report from Cortex using API.
#
# The following steps are performed:
#
# 1. Input Validations
# 2. Fetching Observable Report
# 3. Display the output as per configured fields.
#
#
#
#==========================================#
# LogRhythm SmartResponse Plugin           #
# SmartResponse Configure File             #
# marcos.schejtman@logrhythm.com           #
# Cortex Run Job By ID                     #
# v1  --  September, 2019                  #
#==========================================#

[CmdletBinding()]
param(
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$JobID,
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$Observable,
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$ObservableType
)


# Trap for an exception during the Script
trap [Exception]
{
    if ($PSItem.ToString() -eq "ExecutionFailure")
	{
		exit 1
	}
	elseif (($PSItem.ToString() -eq "ExecutionSuccess"))
	{
		exit
	}
	else
	{
		write-error $("Trapped: $_")
		write-host "Aborting Operation."
		exit
	}
}


# Function to Disable SSL Certificate Error and Enable Tls12
function Disable-SSLError
{
	# Disabling SSL certificate error
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    # Forcing to use TLS1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}


# Function to fetch saved parameter data
function Get-ConfigFileData
{
	try{
		if (!(Test-Path -Path $global:ConfigurationFilePath))
		{
			if ($InputParameterFlag -eq 1){
				write-host "Cortex Configuration File is not present"
				write-error "Error: Config File Not Found. Please run 'Create Cortex Configuration File' action."
				throw "ExecutionFailure"
			}
			else{
				$ConfigFileFlag = 1
			}
		}
		else
		{
			$ConfigFileContent = Import-Clixml -Path $global:ConfigurationFilePath
			$SecureCortexAPIKey = $ConfigFileContent.CortexAPIKey
			$global:CortexAPIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($SecureCortexAPIKey))))
			$global:CortexURL = $ConfigFileContent.CortexURL
			$global:PythonPath = $ConfigFileContent.PythonPath
			$global:HuntingAppRootPath = $ConfigFileContent.HuntingAppRootPath
			$global:CortexJobTimeout = $ConfigFileContent.CortexJobTimeout
			$global:Discover = $ConfigFileContent.Discover
			$global:CleanUp = $ConfigFileContent.CleanUp
		}
	}
	catch{
		$message = $_.Exception.message
		if($message -eq "ExecutionFailure"){
			throw "ExecutionFailure"
		}
		else{
			write-host "Error: User does not have access to Config File."
			write-error $message
			throw "ExecutionFailure"
		}
	}
}


# Function to Invoke external Process
# Original Author: Adam Bertram
# Original Script URL: https://www.powershellgallery.com/packages/Invoke-Process/1.4/Content/Invoke-Process.ps1
function Invoke-Process
{
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ArgumentList
    )

    $ErrorActionPreference = 'Stop'

    try {
        try {
            $stdOutTempFile = "$env:TEMP\$((New-Guid).Guid)"
            $stdErrTempFile = "$env:TEMP\$((New-Guid).Guid)"
        } catch {
            $stdOutTempFile = "$env:TEMP\$([guid]::newguid())"
            $stdErrTempFile = "$env:TEMP\$([guid]::newguid())"
        }

        $startProcessParams = @{
            FilePath               = $FilePath
            ArgumentList           = $ArgumentList
            RedirectStandardError  = $stdErrTempFile
            RedirectStandardOutput = $stdOutTempFile
            Wait                   = $true;
            PassThru               = $true;
            NoNewWindow            = $true;
        }
        if ($PSCmdlet.ShouldProcess("Process [$($FilePath)]", "Run with args: [$($ArgumentList)]")) {
            $cmd = Start-Process @startProcessParams
            $cmdOutput = Get-Content -Path $stdOutTempFile -Raw
            $cmdError = Get-Content -Path $stdErrTempFile -Raw
            if ($cmd.ExitCode -ne 0) {
                if ($cmdError) {
                    throw $cmdError.Trim()
                }
                if ($cmdOutput) {
                    throw $cmdOutput.Trim()
                }
            } 
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    } finally {
        Remove-Item -Path $stdOutTempFile, $stdErrTempFile -Force -ErrorAction Ignore
    }
	return $cmdOutput
}



# Function to get the Cortex Analysis
function Get-Analyzer_by_ID
{
	$execPath = Join-Path -Path $global:PythonPath -ChildPath "python.exe"
	$cortexPath = Join-Path -Path $global:HuntingAppRootPath -ChildPath "\HuntingProviders\Cortex\CortexHuntingProvider.py"
	$output = Invoke-Process -FilePath $execPath -ArgumentList "$cortexPath --cortex_url $global:CortexURL --cortex_key $global:CortexAPIKey job_id --observable $Observable --observable_type $ObservableType --id $JobID"
    Write-Output $output
}
 

# Script Flow Calls and declarations
$InputParameterFlag = 0
$ConfigFileFlag = 0
$global:OutputPrinted = 0
$global:ConfigurationDirectoryPath = "C:\Program Files\LogRhythm\SmartResponse Plugins"
$global:ConfigurationFilePath = "C:\Program Files\LogRhythm\SmartResponse Plugins\CortexConfigFile.xml"


Get-ConfigFileData
Get-Analyzer_by_ID