
Import-Module posh-git
Import-Module Terminal-Icons

# Function Get-PrivilegeForPrompt {
#     # Shout out to the Stack Overflow article that helped with this test.
#     # https://serverfault.com/questions/95431/in-a-powershell-script-how-can-i-check-if-im-running-with-administrator-privil
#     if ($IsWindows) {
#         $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
#         if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
#             "n$env:USERNAME as Administrator on $(hostname)n$pwd`nPS > "
#         } else {
#             "n$env:USERNAME as standard user on $(hostname)n$pwd`nPS > "
#         }
#     }

#     if ($isLinux -Or $isMac) {
#         "n$env:USERNAME on $(hostname)n$pwd`nPS > "
#     }
# }

Function Get-PublicIP {
 (Invoke-WebRequest http://ifconfig.me/ip ).Content
}

Function Get-Zulu {
    Get-Date -Format u
}

Function Get-SortableDate {
    (Get-Date).ToString('s')
}

Function Get-UpTime {
    Get-WmiObject win32_operatingsystem | `
        Select-Object csname, @{
        LABEL      = 'LastBootUpTime';
        EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) }
    }
}

Function Find-File($name) {
    Get-ChildItem -Recurse -Filter "*${name}*" -ErrorAction SilentlyContinue | `
        ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}

Function Expand-ZipFile ($file) {
    $dirname = (Get-Item $file).Basename
    Write-Output('Extracting', $file, 'to', $dirname)
    New-Item -Force -ItemType directory -Path $dirname
    Expand-Archive $file -OutputPath $dirname -ShowProgress
}

Function Get-Identity {
    [Security.Principal.WindowsIdentity]::GetCurrent()
}

Function Get-Principal {
    $identity = Get-Identity
    New-Object Security.Principal.WindowsPrincipal $identity
}

Function Get-IsAdmin {
    $principal = Get-Principal
    $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

Function Get-Md5 ($file) {
    Get-FileHash -Algorithm MD5 $file | Select-Object -ExpandProperty Hash
}

Function Get-Sha1 ($file) {
    Get-FileHash -Algorithm SHA1 $file | Select-Object -ExpandProperty Hash
}

Function Get-Sha256 ($file) {
    Get-FileHash -Algorithm SHA256 $file | Select-Object -ExpandProperty Hash
}

Function Get-Dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | ForEach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | ForEach-Object FullName
    }
}

Function Set-Folder ($Path) {
    If (!(Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

Function Invoke-Transcript {
    $transcriptDirectory = '~\transcripts\'
    $transcriptLog = (hostname) + '_' + $env:USERNAME + '_' + (Get-Date -UFormat '%Y-%m-%d')
    $trascriptPath = $transcriptDirectory + $transcriptLog

    If (!(Test-Path -Path $transcriptDirectory)) {
        Write-Verbose 'Trasnscripts is missing'
        Write-Verbose 'Creating ~\.transcripts'
        New-Item -ItemType Directory -Path ~\.transcripts | Out-Null
    }

    Start-Transcript -LiteralPath $TrascriptPath -Append
}

Function Sync-DotFile {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $ConfigFullName,

        [String]
        [Parameter(Position = 1, mandatory = $true)]
        $BackupPath
    )

    Begin {
        If (!(Test-Path -Path $ConfigFullName)) {
            Write-Error "Configuration file does not exist at $ConfigFileFullName"
        }
        Set-Folder -Path $BackupPath
    }

    Process {
        $fileName = [System.IO.Path]::GetFileName($ConfigFullname)
        Get-Content -Path $ConfigFullName | `
            Set-Content -Force -Path "$BackupPath\$fileName"

    }

}

Function Sync-DotFiles {
    $computerName = $env:COMPUTERNAME
    $gitRepo = 'D:\code\github\dot_files'
    $location = "$gitRepo\$computerName"
    Set-Folder -Path $location
    Sync-DotFile -ConfigFullName $profile -BackupPath "$location\PowerShell"

    $wsl = '~\.wslconfig'
    Sync-DotFile -ConfigFullName $wsl -BackupPath "$location\WSL"

    $vsCodeUser = '~\AppData\Roaming\Code\User\settings.json'
    Sync-DotFile -ConfigFullName $vsCodeUser -BackupPath "$location\VSCode"

    $currentDirectory = Get-Location
    Set-Location -Path $gitRepo
    $gitStatus = Get-GitStatus
    If ($gitStatus.HasWorking) {
        # $sortableDate = Get-SortableDate
        # git add -A; git commit -a -m "'$sortableDate'"; git push
    }
    Else {
        Write-Host -ForegroundColor Green 'Dot Files Have Not Changed'
    }
    Set-Location -Path $currentDirectory
}

Function Get-VersionValues {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Version
    )

    Begin {
        $pattern = '(?<Major>\d{1,2})(?:\.)(?<Minor>\d{1,2})(?:\.)(?<Patch>\d{1,2})'
    }

    Process {
        $versionMatches =
        Select-String -AllMatches -Pattern $pattern -InputObject $Version | `
            Select-Object -ExpandProperty Matches

        $version = $versionMatches.Groups | `
            Where-Object { $_.Name -eq '0' } | `
            Select-Object -ExpandProperty Value

        $major = $versionMatches.Groups | `
            Where-Object { $_.Name -eq 'Major' } | `
            Select-Object -ExpandProperty Value

        $minor = $versionMatches.Groups | `
            Where-Object { $_.Name -eq 'Minor' } | `
            Select-Object -ExpandProperty Value

        $patch = $versionMatches.Groups | `
            Where-Object { $_.Name -eq 'Patch' } | `
            Select-Object -ExpandProperty Value

        [PSCustomObject] @{
            Version = $version;
            Major   = $major;
            Minor   = $minor;
            Patch   = $patch;
            IsValid = $null -ne $version;
        }
    }
}

Function Add-NpmLatestVersion {
    [CmdletBinding()]
    Param(
        [string]
        [Parameter(Position = 0, mandatory = $true)]
        $Package,

        [psobject]
        [Parameter(Position = 1, mandatory = $true)]
        $Installed
    )

    Process {
        $installed | `
            Add-Member -NotePropertyName 'IsLatest' -NotePropertyValue $null

        $installed | `
            Add-Member -NotePropertyName 'LatestVersion' -NotePropertyValue $null

        TRAP { '' ; continue }
        $latestVersion = npm view $Package version

        $latest = Get-VersionValues -Version $latestVersion

        If ($installed.IsValid -and $latest.IsValid) {
            If ($null -eq $installed.IsLatest -and $installed.Major -lt $latest.Major) {
                $installed.IsLatest = $false
                $installed.LatestVersion = $latest.Version
            }

            If ($null -eq $installed.IsLatest -and $installed.Minor -lt $latest.Minor) {
                $installed.IsLatest = $false
                $installed.LatestVersion = $latest.Version
            }

            If ($null -eq $installed.IsLatest -and $installed.Patch -lt $latest.Patch) {
                $installed.IsLatest = $false
                $installed.LatestVersion = $latest.Version
            }

            If ($null -eq $installed.IsLatest) {
                $installed.IsLatest = $true
                $installed.LatestVersion = $latest.Version
            }
        }

        $installed
    }
}

Function Get-NodeVersion {
    $pattern = '(?:v)(?<Version>.*)'

    TRAP { '' ; continue }
    $nodeVersion = node --version

    $nodeVersionMatches =
    Select-String -AllMatches -Pattern $pattern -InputObject $nodeVersion | `
        Select-Object -ExpandProperty Matches

    $version = $nodeVersionMatches.Groups | `
        Where-Object { $_.Name -eq 'Version' } | `
        Select-Object -ExpandProperty Value

    If ($null -eq $version) {
        Write-Errror 'Failed to Node Version'
    }

    Get-VersionValues -Version $version
}

Function Test-NodeVersion {
    Process {
        $nodeVersion = Get-NodeVersion

        If ($nodeVersion.IsValid) {
            Return $true
        }

        Return $false
    }
}

Function Get-NpmVersion {
    Process {
        TRAP { '' ; continue }
        $installedVersion = npm --version

        If ($null -eq $installedVersion) {
            Write-Warning 'NPM is not Installed.'
            Return [PSCustomObject] @{
                Version = $null;
                Major   = $null;
                Minor   = $null;
                Patch   = $null;
                IsValid = $false;
            }
        }

        $installed = Get-VersionValues -Version $installedVersion

        if ($null -eq $installed) {
            Write-Error 'Failed to get NPM Version.'
        }

        if ($installed.IsValid -eq $false) {
            Write-Warning 'NPM Version is Invalid.'
            Return $installed
        }

        Add-NpmLatestVersion -Package 'npm' -Installed $installed
    }
}

Function Test-NpmVersion {
    Process {
        $npmVersion = Get-NpmVersion

        If ($npmVersion.IsValid) {
            Return $true
        }

        Return $false
    }
}

Function Get-YarnVersion {
    Process {
        TRAP { '' ; continue }
        $installedVersion = yarn --version

        If ($null -eq $installedVersion) {
            Write-Warning 'Yarn is not Installed.'
            Return [PSCustomObject] @{
                Version = $null;
                Major   = $null;
                Minor   = $null;
                Patch   = $null;
                IsValid = $false;
            }
        }

        $installed = Get-VersionValues -Version $installedVersion

        if ($null -eq $installed) {
            Write-Error 'Failed to get Yarn Version.'
        }

        if ($installed.IsValid -eq $false) {
            Write-Warning 'Yarn Version is Invalid.'
            Return $installed
        }

        Add-NpmLatestVersion -Package 'yarn' -Installed $installed
    }
}

Function Test-YarnVersion {
    Process {
        $yarnVersion = Get-YarnVersion

        If ($yarnVersion.IsValid) {
            Return $true
        }

        Return $false
    }
}
Function Get-AngularVersion {
    Process {
        TRAP { '' ; continue }
        $installedVersion = ng --version

        If ($null -eq $installedVersion) {
            Write-Warning 'Angular is not Installed.'
            Return [PSCustomObject] @{
                Version = $null;
                Major   = $null;
                Minor   = $null;
                Patch   = $null;
                IsValid = $false;
            }
        }

        $installed = Get-VersionValues -Version $installedVersion

        if ($null -eq $installed) {
            Write-Error 'Failed to get Yarn Version.'
        }

        if ($installed.IsValid -eq $false) {
            Write-Warning 'Yarn Version is Invalid.'
            Return $installed
        }

        $installed

        # npm view @angular/cli version fails when called
        #Add-NpmLatestVersion -Package '@angluar/cli' -Installed $installed
    }
}

Function Test-AngularVersion {
    Process {
        $angularVersion = Get-AngularVersion

        If ($angularVersion.IsValid) {
            Return $true
        }

        Return $false
    }
}

Function Install-Yarn {
    Begin {
        If ($nodeVersion.IsValid -eq $false) {
            Write-Error 'Node Version is Invalid.'
        }

        If ($npmVersion.IsValid -eq $false) {
            Write-Error 'NPM Version is Invalid.'
        }

        $yarnVersion = Get-YarnVersion

        If ($yarnVersion.IsValid -and $yarnVersion.IsLatest) {
            Return
        }
    }

    Process {
        Write-Warning 'Not Implemented ... Yet.'
    }
}

Function Install-GlobalNpmPackages {
    Begin {
        If ($nodeVersion.IsValid -eq $false) {
            Write-Error 'Node Version is Invalid.'
        }

        If ($npmVersion.IsValid -eq $false) {
            Write-Error 'NPM Version is Invalid.'
        }
    }

    Process {
        Write-Output 'Installing latest NPM ...'
        npm install --global npm

        Write-Output 'Installing latest yarn ...'
        npm install --global yarn

        Write-Output 'Installing latest @angular/cli ...'
        npm install --global @angular/cli

        Write-Output 'Installing latest npm-check-updates ...'
        npm install --global npm-check-updates
    }
}

Function New-AngularApplication {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Name
    )

    Begin {
        Install-GlobalNpmPackages

        $nodeIsValid = Test-NodeVersion
        If ($nodeIsValid -eq $false) {
            throw 'Node is not installed.'
            Return
        }

        $npmVersionIsValid = Test-NpmVersion
        If ($npmVersionIsValid -eq $false) {
            throw 'NPM is not installed.'
            Return
        }

        $yarnVersionIsValid = Test-YarnVersion
        If ($yarnVersionIsValid -eq $false) {
            throw 'Yarn is not installed.'
            Return
        }

        $angularVersionIsValid = Test-AngularVersion
        If ($angularVersionIsValid -eq $false) {
            throw 'Angular is not installed.'
            Return
        }
    }

    Process {
        ng new "$Name.Web" `
            --package-manager yarn `
            --ssr false `
            --routing true `
            --skip-git true `
            --skip-tests true `
            --style scss `
            --strict

        Set-Location "$Name.Web"

        ng add @angular-eslint/schematics --skip-confirmation
        yarn add -D @angular-devkit/schematics
        yarn add -D @angular-devkit/core
        yarn add -D @typescript-eslint/parser
        yarn add -D @typescript-eslint/eslint-plugin
        yarn add -D @typescript-eslint/utils

        yarn add -D eslint
        yarn add -D eslint-config-angular

        yarn add -D eslint-detailed-reporter
        yarn add -D eslint-plugin-lodash
        yarn add -D eslint-plugin-lodash

        yarn add -D prettier
        yarn add -D prettier-eslint
        yarn add -D eslint-config-prettier
        yarn add -D eslint-plugin-prettier

        yarn add -D eslint-import-resolver-typescript
        yarn add -D eslint-plugin-angular
        yarn add -D eslint-plugin-array-func
        yarn add -D eslint-plugin-const-case
        yarn add -D eslint-plugin-import
        yarn add -D eslint-plugin-json
        yarn add -D eslint-plugin-json-format
        yarn add -D eslint-plugin-jsonc
        yarn add -D eslint-plugin-no-argument-spread
        yarn add -D eslint-plugin-no-constructor-bind
        yarn add -D eslint-plugin-no-loops
        yarn add -D eslint-plugin-no-secrets
        yarn add -D eslint-plugin-no-unsanitized
        yarn add -D eslint-plugin-no-use-extend-native
        yarn add -D eslint-plugin-pii
        yarn add -D eslint-plugin-regexp
        yarn add -D eslint-plugin-security
        yarn add -D eslint-plugin-simple-import-sort
        yarn add -D eslint-plugin-sonarjs
        yarn add -D eslint-plugin-sort-keys-fix
        yarn add -D eslint-plugin-unicorn
        yarn add -D eslint-plugin-unused-imports
        yarn add -D eslint-plugin-write-good-comments

        npx --package npm-check-updates ncu --target minor -u

        yarn install

        Set-Location '..\'
    }
}

Function New-CoreProject {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Name
    )

    Process {
        dotnet new classlib `
            --name "$Name.Core" `
            --language 'C#' `
            --framework net8.0

        Set-Location -Path "$Name.Core"

        dotnet add package AspNetCoreAnalyzers
        dotnet add package Documentation.Analyser
        dotnet add package IDisposableAnalyzers
        dotnet add package Meziantou.Analyzer
        dotnet add package Microsoft.CodeAnalysis.CSharp
        dotnet add package Microsoft.CodeAnalysis.CSharp.Workspaces
        dotnet add package Microsoft.VisualStudio.Threading.Analyzers
        dotnet add package ReflectionAnalyzers
        dotnet add package Roslynator.Analyzers
        dotnet add package SonarAnalyzer.CSharp
        dotnet add package StyleCop.Analyzers

        dotnet add package Microsoft.Extensions.Configuration
        dotnet add package Microsoft.Extensions.Configuration.Binder
        dotnet add package Microsoft.Extensions.DependencyInjection

        dotnet add package Microsoft.Data.SqlClient
        dotnet add package Dapper

        Set-Location -Path '..\'
    }
}

Function New-DataProject {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Name
    )

    Begin {
        Function Add-DataProjectPackages {
            dotnet add package AspNetCoreAnalyzers
            dotnet add package Documentation.Analyser
            dotnet add package IDisposableAnalyzers
            dotnet add package Meziantou.Analyzer
            dotnet add package Microsoft.CodeAnalysis.CSharp
            dotnet add package Microsoft.CodeAnalysis.CSharp.Workspaces
            dotnet add package Microsoft.VisualStudio.Threading.Analyzers
            dotnet add package ReflectionAnalyzers
            dotnet add package Roslynator.Analyzers
            dotnet add package SonarAnalyzer.CSharp
            dotnet add package StyleCop.Analyzers

            dotnet add package Microsoft.Extensions.Hosting
            dotnet add package Microsoft.Extensions.DependencyInjection
            dotnet add package System.CommandLine --prerelease
            dotnet add package System.CommandLine.Hosting --prerelease

            dotnet add package Serilog
            dotnet add package Serilog.AspNetCore
            dotnet add package Serilog.Sinks.Console
            dotnet add package Serilog.Sinks.Debug
            dotnet add package Serilog.Sinks.File
            dotnet add package Serilog.Sinks.ApplicationInsights
            dotnet add package SerilogAnalyzer
        }
    }

    Process {
        dotnet new console `
            --name "$Name.Data" `
            --language 'C#' `
            --framework net8.0

        Set-Location -Path "$Name.Data"

        Add-DataProjectPackages

        Set-Location -Path '..\'

        dotnet new console `
            --name "$Name.Data.Local" `
            --language 'C#' `
            --framework net8.0

        Set-Location -Path "$Name.Data.Local"

        Add-DataProjectPackages

        Set-Location -Path '..\'
    }
}

Function New-MigrationProject {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Name
    )

    Process {
        dotnet new classlib `
            --name "$Name.Migrations" `
            --language 'C#' `
            --framework net8.0

        Set-Location -Path "$Name.Migrations"

        dotnet add package AspNetCoreAnalyzers
        dotnet add package Documentation.Analyser
        dotnet add package IDisposableAnalyzers
        dotnet add package Meziantou.Analyzer
        dotnet add package Microsoft.CodeAnalysis.CSharp
        dotnet add package Microsoft.CodeAnalysis.CSharp.Workspaces
        dotnet add package Microsoft.VisualStudio.Threading.Analyzers
        dotnet add package ReflectionAnalyzers
        dotnet add package Roslynator.Analyzers
        dotnet add package SonarAnalyzer.CSharp
        dotnet add package StyleCop.Analyzers

        dotnet add package FluentMigrator
        dotnet add package FluentMigrator.Runner
        dotnet add package FluentMigrator.Runner.SqlServer

        Set-Location -Path '..\'
    }
}

Function New-TestProject {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, mandatory = $true)]
        [String]
        $Name,

        [Parameter(Position = 1, mandatory = $true)]
        [ValidateSet('Api', 'Core', IgnoreCase = $false)]
        [string]
        $Type
    )

    Process {
        dotnet new xunit `
            --name "$Name.Tests.$Type" `
            --language 'C#' `
            --framework net8.0

        Set-Location -Path "$Name.Tests.$Type"

        dotnet add package AspNetCoreAnalyzers
        dotnet add package Documentation.Analyser
        dotnet add package IDisposableAnalyzers
        dotnet add package Meziantou.Analyzer
        dotnet add package Microsoft.CodeAnalysis.CSharp
        dotnet add package Microsoft.CodeAnalysis.CSharp.Workspaces
        dotnet add package Microsoft.VisualStudio.Threading.Analyzers
        dotnet add package ReflectionAnalyzers
        dotnet add package Roslynator.Analyzers
        dotnet add package SonarAnalyzer.CSharp
        dotnet add package StyleCop.Analyzers

        dotnet add package xUnit.Analyzers

        Set-Location -Path '..\'
    }
}

Function New-ApiProject {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Name
    )

    Process {
        dotnet new webapi `
            --name "$Name.Api" `
            --language 'C#' `
            --framework net8.0

        Set-Location -Path "$Name.Api"

        dotnet add package AspNetCoreAnalyzers
        dotnet add package Documentation.Analyser
        dotnet add package IDisposableAnalyzers
        dotnet add package Meziantou.Analyzer
        dotnet add package Microsoft.CodeAnalysis.CSharp
        dotnet add package Microsoft.CodeAnalysis.CSharp.Workspaces
        dotnet add package Microsoft.VisualStudio.Threading.Analyzers
        dotnet add package ReflectionAnalyzers
        dotnet add package Roslynator.Analyzers
        dotnet add package SonarAnalyzer.CSharp
        dotnet add package StyleCop.Analyzers

        dotnet add package Serilog
        dotnet add package Serilog.AspNetCore
        dotnet add package Serilog.Sinks.Console
        dotnet add package Serilog.Sinks.Debug
        dotnet add package Serilog.Sinks.File
        dotnet add package Serilog.Sinks.ApplicationInsights
        dotnet add package SerilogAnalyzer

        Set-Location -Path '..\'
    }
}

Function New-DotNetSolution {
    [CmdletBinding()]
    Param(
        [String]
        [Parameter(Position = 0, mandatory = $true)]
        $Name
    )

    Process {
        New-Item -ItemType Directory -Path "$Name"

        Set-Location -Path "$Name"

        dotnet new sln --name "$Name"

        New-ApiProject -Name "$Name"
        New-CoreProject -Name "$Name"
        New-DataProject -Name "$Name"
        New-MigrationProject -Name "$Name"
        New-TestProject -Name "$Name" -Type Api
        New-TestProject -Name "$Name" -Type Core

        dotnet sln add "$Name.Api"
        dotnet sln add "$Name.Core"
        dotnet sln add "$Name.Data"
        dotnet sln add "$Name.Data.Local"
        dotnet sln add "$Name.Migrations"
        dotnet sln add "$Name.Tests.Api"
        dotnet sln add "$Name.Tests.Core"

        New-AngularApplication -Name "$Name"

        Set-Location -Path '..\'
    }
}


Function Export-DrawIO {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, mandatory = $true)]
        [String]
        $File
    )

    Process {
        $content = Get-Content -Path $File
        $pattern = '(?:name=")(?<Name>.*?)(?:")'
        $pages = $content | Select-String -Pattern $pattern
        $regex = [Regex]::new($pattern)

        $pageCount = 0
        ForEach ($page in $pages) {
            Write-Host "Exporting Page: $page"

            $name = $regex.Matches($page) | `
                Select-Object -ExpandProperty Groups | `
                Where-Object { $_.Name -eq 'Name' } | `
                Select-Object -ExpandProperty Value

            $output = "$File_$name.svg"
            draw.io.exe `
                --export `
                --output $output `
                --format svg `
                --transparent `
                --svg-theme light `
                --embed-svg-images `
                --page-index $pageCount `
                $File

            $output = "$File_$name.png"
            draw.io.exe `
                --export `
                --output $output `
                --format png `
                --transparent `
                --svg-theme light `
                --embed-svg-images `
                --page-index $pageCount `
                $File

            $pageCount++
        }
    }
}

$ohMyPoshConfig = 'C:\Users\RustyHann\AppData\Local\Programs\oh-my-posh\themes\zero-allocation.omp.json'
oh-my-posh init pwsh --config $ohMyPoshConfig | Invoke-Expression

Invoke-Transcript
#Sync-DotFiles

