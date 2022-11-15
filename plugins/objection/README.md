# Use Objection from r2frida! (EXPERIMENTAL)

With this plugin you can enable and disable the jailbreak check bypasses of Objection

Note that this is a 5 minute hack and there's still many things to be done to get
all the probes available

## How to use

```bash
$ r2 frida://spawn/usb//Twitter
> :. r2f-objection-plugin.js
> :objection
iosJailbreakDisable
iosJailbreakEnable
...
> :objection iosJailbreakEnable
```

## Listing actions

The `:objection` command created by this plugin takes an argument of the probe name

* `:objection -a` - list all the actions (some require arguments to work)
* `:objection` - list known-to-work probes
* `:objection [probename]` - run this action

## How to build

```bash
> make
.. will download objection ..
.. compile the agent ..
.. concat the r2frida-plugin logic ..
>
```

## Full list of

* androidMonitorClipboard
* androidDeoptimize
* androidShellExec
* androidFileCwd
* androidFileDelete
* androidFileDownload
* androidFileExists
* androidFileLs
* androidFilePathIsFile
* androidFileReadable
* androidFileUpload
* androidFileWritable
* androidHookingGetClassMethods
* androidHookingGetClassMethodsOverloads
* androidHookingGetClasses
* androidHookingGetClassLoaders
* androidHookingGetCurrentActivity
* androidHookingListActivities
* androidHookingListBroadcastReceivers
* androidHookingListServices
* androidHookingSetMethodReturn
* androidHookingWatch
* androidHookingEnumerate
* androidHookingLazyWatchForPattern
* androidHeapEvaluateHandleMethod
* androidHeapExecuteHandleMethod
* androidHeapGetLiveClassInstances
* androidHeapPrintFields
* androidHeapPrintMethods
* androidIntentStartActivity
* androidIntentStartService
* androidKeystoreClear
* androidKeystoreList
* androidKeystoreDetail
* androidKeystoreWatch
* androidSslPinningDisable
* androidProxySet
* androidRootDetectionDisable
* androidRootDetectionEnable
* androidUiScreenshot
* androidUiSetFlagSecure
* iosBinaryInfo
* iosCookiesGet
* iosCredentialStorage
* iosFileCwd
* iosFileDelete
* iosFileDownload
* iosFileExists
* iosFileLs
* iosFilePathIsFile
* iosFileReadable
* iosFileUpload
* iosFileWritable
* iosHeapEvaluateJs
* iosHeapExecMethod
* iosHeapPrintIvars
* iosHeapPrintLiveInstances
* iosHeapPrintMethods
* iosHookingGetClassMethods
* iosHookingGetClasses
* iosHookingSetReturnValue
* iosHookingWatch
* iosHookingSearch
* iosMonitorCryptoEnable
* iosJailbreakDisable
* iosJailbreakEnable
* iosPlistRead
* iosUiAlert
* iosUiBiometricsBypass
* iosUiScreenshot
* iosUiWindowDump
* iosPinningDisable
* iosMonitorPasteboard
* iosBundlesGetBundles
* iosBundlesGetFrameworks
* iosKeychainAdd
* iosKeychainEmpty
* iosKeychainList
* iosKeychainListRaw
* iosNsuserDefaultsGet
* envAndroid
* envAndroidPaths
* envFrida
* envIos
* envIosPaths
* envRuntime
* jobsGet
* jobsKill
* memoryDump
* memoryListExports
* memoryListModules
* memoryListRanges
* memorySearch
* memoryWrite
* evaluate
* httpServerStart
* httpServerStatus
* httpServerStop
* ping
