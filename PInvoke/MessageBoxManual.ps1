$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
$TypeBuilder = $ModuleBuilder.DefineType('User32', 'Public, Class')


$PInvokeMethod = $TypeBuilder.DefineMethod(
	'MessageBox',
	[Reflection.MethodAttributes] 'Public, Static',
	[Int32],
	[Type[]] @([IntPtr], [String], [String], [Int32])
)

$DllImportConstructor = [System.Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$FieldArray = [System.Reflection.FieldInfo[]] @(
	[System.Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
	[System.Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
)

$FieldValueArray = [Object[]] @(
	'MessageBoxW',
	$true,
	$true,
	[System.Runtime.InteropServices.CallingConvention]::Winapi,
	[System.Runtime.InteropServices.CharSet]::Unicode
)

$SetLastErrorCustomAttribute = New-Object System.Reflection.Emit.CustomAttributeBuilder(
	$DLLImportConstructor,
	@('user32.dll'),
	$FieldArray,
	$FieldValueArray
)

$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
$User32 = $TypeBuilder.CreateType()
