
#
# Module Manifest for Module 'NITProcessTools.psd1
#
#

@{

# Module Loader File
RootModule = 'loader.psm1'

# Version Number
ModuleVersion = '1.0'

# Unique Module ID
GUID = 'd70e9de4-81dc-493d-9b6a-e18a7dc760dd'

# Module Author
Author = 'Andreas Nick'

# Company
CompanyName = 'NIT'

# Copyright
Copyright = '(c) 2021 Andreas Nick. All rights reserved.'

# Module Description
Description = 'A module to determine the percentage CPU usage for processes'

# Minimum PowerShell Version Required
PowerShellVersion = '5.1'

# Name of Required PowerShell Host
PowerShellHostName = ''

# Minimum Host Version Required
PowerShellHostVersion = ''

# Minimum .NET Framework-Version
DotNetFrameworkVersion = ''

# Minimum CLR (Common Language Runtime) Version
CLRVersion = ''

# Processor Architecture Required (X86, Amd64, IA64)
ProcessorArchitecture = 'Amd64'

# Required Modules (will load before this module loads)
RequiredModules = @()

# Required Assemblies
RequiredAssemblies = @('NITProcessTools.dll')

# PowerShell Scripts (.ps1) that need to be executed before this module loads
ScriptsToProcess = @()

# Type files (.ps1xml) that need to be loaded when this module loads
TypesToProcess = @()

# Format files (.ps1xml) that need to be loaded when this module loads
FormatsToProcess = @()

# 
NestedModules = @('NITProcessTools')

# List of exportable functions
FunctionsToExport = '*'

# List of exportable cmdlets
CmdletsToExport = '*'

# List of exportable variables
VariablesToExport = ''

# List of exportable aliases
AliasesToExport = '*'

# List of all modules contained in this module
ModuleList = @()


# List of all files contained in this module
FileList = @('NITProcessTools.dll')

# Private data that needs to be passed to this module
PrivateData = ''

}