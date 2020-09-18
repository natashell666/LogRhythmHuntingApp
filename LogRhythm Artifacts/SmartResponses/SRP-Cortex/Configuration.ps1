# Requires -Version 3.0
# 
# This Script is used to configure fixed parameters for a plugin so as they need not to be provided everytime while executing an action.
#
# Use Case -> 
# Configure Fixed parameters in a one time script run. For Ex API Key, Username, Password
# Store parameter values in encrypted form.
# 
# The following steps are performed:
#
# 1. Input Validations.
# 2. Creating a file to store parameter values.
# 3. Enctypting the parameter values.
# 4. Storing the parameter values in the file.
#
### ===============================================================================================#
### Change the Value of ConfigurationFilePath for each Plugin                              #########          
### Change the dictionary Key Values for use in the individual Plugin.                     #########
###                                                                                        #########
###                                                                                        #########
###================================================================================================#
# 
#==========================================#
# LogRhythm SmartResponse Plugin           #
# SmartResponse Configure File             #
# marcos.schejtman@logrhythm.com           #
# Cortex Config File             		   #
# v1.0  --  September, 2020                #
#==========================================#


[CmdletBinding()]
param(
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$CortexAPIKey,
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$CortexAPIUrl,
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$PythonPath,
[Parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$HuntingAppRootPath,
[string]$WaitTime
)


# Trap for an exception during the Script
trap [Exception]
{
    if ($PSItem.ToString() -eq "ExecutionFailure")
	{
		exit 1
	}
	else
	{
		write-error $("Trapped: $_")
		write-host "Aborting Operation."
		exit
	}
}


# Function to Check and Create SmartResponse Directory
function Create-SRPDirectory
{
	if (!(Test-Path -Path $global:ConfigurationDirectoryPath))
	{
		New-Item -ItemType "directory" -Path $global:ConfigurationDirectoryPath -Force | Out-null
	}
}


# Function to Check and Create SmartResponse Config File
function Check-ConfigFile
{
	if (!(Test-Path -Path $global:ConfigurationFilePath))
	{
		New-Item -ItemType "file" -Path $global:ConfigurationFilePath -Force | Out-null
	}
}


# Function to Create Hashtable for the parameters
function Create-Hashtable
{
    if (($WaitTime -eq "") -or ($WaitTime -eq $null)){
	    $WaitTime = 30
    }

	$global:HashTable = [PSCustomObject]@{
								"CortexAPIKey" = $SecureCortexAPIKey
								"CortexURL" = $CortexAPIUrl
								"PythonPath" = $PythonPath
								"HuntingAppRootPath" = $HuntingAppRootPath
								"CortexJobTimeout" = $WaitTime
								"Discover" = $true
								"CleanUp" = $false
						}
}


# Function to Create Config File
function Create-ConfigFile
{
	$global:HashTable | Export-Clixml -Path $global:ConfigurationFilePath
	write-host "Configuration Parameters validations passed for Cortex SRP and Config File Created."
	
}


$global:ConfigurationDirectoryPath = "C:\Program Files\LogRhythm\SmartResponse Plugins"
$global:ConfigurationFilePath = "C:\Program Files\LogRhythm\SmartResponse Plugins\CortexConfigFile.xml"

Create-SRPDirectory
Check-ConfigFile

$CortexAPIKey = $CortexAPIKey.Trim()
$SecureCortexAPIKey = $CortexAPIKey | ConvertTo-SecureString -AsPlainText -Force

Create-Hashtable
Create-ConfigFile