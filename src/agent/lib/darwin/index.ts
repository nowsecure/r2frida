import { getGlobalExportByName, padPointer, trunc4k, autoType } from '../utils.js';
import { PathTransform, VirtualEnt, flatify, nsArrayMap } from '../fs.js';
import { listClasses } from '../info/classes.js';
import ObjC from "frida-objc-bridge";
import Java from "frida-java-bridge";

const MIN_PTR = ptr('0x100000000');
const ISA_MASK = ptr('0x0000000ffffffff8');
const ISA_MAGIC_MASK = ptr('0x000003f000000001');
const ISA_MAGIC_VALUE = ptr('0x000001a000000001');

/* ObjC.available is buggy on non-objc apps, so override this */
export const ObjCAvailable = (Process.platform === 'darwin') && !(Java && Java.available) && ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';

export function initFoundation(): void {
    // required for early instrumentation
    try {
        Module.load('/System/Library/Frameworks/Foundation.framework/Foundation');
        Module.load('/System/Library/PrivateFrameworks/AppSSOCore.framework/AppSSOCore');
    } catch (e) {
        // ignored
    }
}

export function getIOSVersion(): string {
    if (!ObjCAvailable) {
        return '?';
    }
    const processInfo = ObjC.classes.NSProcessInfo.processInfo();
    const versionString = processInfo.operatingSystemVersionString().UTF8String().toString();
    // E.g. "Version 13.5 (Build 17F75)"
    const version = versionString.split(' ')[1];
    // E.g. 13.5
    return version;
}

export function isiOS(): boolean {
    return Process.platform === 'darwin' &&
        Process.arch.indexOf('arm') === 0 &&
        ObjC.available;
}

export function isValidObjC(addr: NativePointer): boolean {
    const klass = getObjCClassfromPointer(addr);
    return !klass.isNull();
}

export function getObjCClassfromPointer(addr: NativePointer): NativePointer {
    if (!isAddressInRange(addr) || !isReadable(addr)) {
        return NULL;
    }
    const isa = addr.readPointer();
    let classP = isa;
    if (classP.and(ISA_MAGIC_MASK).equals(ISA_MAGIC_VALUE)) {
        classP = isa.and(ISA_MASK);
    }
    return isAddressInRange(classP) ? classP : NULL;
}

export function isAddressInRange(addr: NativePointer): boolean {
    return addr.compare(MIN_PTR) >= 0;
}

export function isReadable(addr: NativePointer): boolean {
    // TODO: catching access violation isn't compatible with jailed testing
    try {
        addr.readU8();
        return true;
    } catch (e) {
        return false;
    }
}

export function callObjcMethod(args: string[]): string {
    if (!ObjCAvailable) {
        return "dxo requires the objc runtime to be available to work.";
    }
    if (args.length === 0) {
        return "Usage: dxo [klassname|instancepointer] [methodname] [args...]";
    }
    if (args.length === 1) {
        return listClasses(args);
    }
    // Usage: "dxo instance-pointer [arg0 arg1]"
    let instancePointer : any | null = null;
    if (args[0].startsWith('0x')) {
        instancePointer = new ObjC.Object(ptr(args[0]));
    } else {
        const klassName = args[0];
        if (!ObjC.classes[klassName]) {
            return `Cannot find objc class ${klassName}`;
        }
        const instances = ObjC.chooseSync(ObjC.classes[klassName]);
        if (!instances || instances[0] === undefined) {
            return `Cannot find any instance for klass ${klassName}`;
        }
        instancePointer = instances[0];
    }
    const methodName = args[1];
    const [v, t] = autoType(args.slice(2)); // eslint-disable-line no-unused-vars
    try {
        ObjC.schedule(ObjC.mainQueue, function () {
            if (Object.prototype.hasOwnProperty.call(instancePointer, methodName)) {
                const retval = instancePointer[methodName](...t);
                if (retval !== undefined && retval !== null && !retval.isNull()) {
                    if (retval.class !== undefined) {
                        console.log((new ObjC.Object(retval)).toString());
                    } else {
                        console.log(retval);
                    }
                }
            } else {
                console.error(`unknown method ${methodName} for objc instance at ${padPointer(instancePointer)}`);
            }
        });
    } catch (e) {
        console.error(e);
    }
    return '';
}
export function hasMainLoop(): boolean {
    const getMainPtr = getGlobalExportByName('CFRunLoopGetMain');
    const copyCurrentModePtr = getGlobalExportByName('CFRunLoopCopyCurrentMode');
    if (getMainPtr === null || copyCurrentModePtr === null) {
        return false;
    }
    const getMain = new NativeFunction(getMainPtr, 'pointer', []);
    const copyCurrentMode = new NativeFunction(copyCurrentModePtr, 'pointer', ['pointer']);
    const main = getMain();
    if (main.isNull()) {
        return false;
    }
    const mode = copyCurrentMode(main);
    const hasLoop = !mode.isNull();
    if (hasLoop) {
        new ObjC.Object(mode).release();
    }
    return hasLoop;
}

export function uiAlert(args: string[]): string {
    if (args.length < 2) {
        return 'Usage: ?E title message';
    }
    const title = args[0];
    const message = args.slice(1).join(' ');
    ObjC.schedule(ObjC.mainQueue, function () {
        const UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
        const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(title, message, NULL, 'OK', NULL);
        view.show();
        view.release();
    });
    return 'alert triggered';
}

export function listMachoSegments(baseAddr: NativePointer) {
    if (!_isMachoHeaderAtOffset(baseAddr)) {
        throw new Error(`Not a valid Mach0 module found at ${baseAddr}`);
    }
    const machoHeader = parseMachoHeader(baseAddr);
    if (machoHeader !== undefined) {
        return getSegments(baseAddr, machoHeader.ncmds);
    }
    return [];
}

export function listMachoSections(baseAddr: NativePointer) : any[] {
    const result : any[] = [];
    if (!_isMachoHeaderAtOffset(baseAddr)) {
        throw new Error(`Not a valid Mach0 module found at ${baseAddr}`);
    }
    const machoHeader = parseMachoHeader(baseAddr);
    if (machoHeader !== undefined) {
        const segments = getSegments(baseAddr, machoHeader.ncmds);
        segments
            .filter((segment) => segment.name === '__TEXT' || segment.name === '__DATA')
            .forEach((segment) => {
                result.push(...getSections(segment));
            });
    }
    return result;
}

export function parseMachoHeader(offset: NativePointer) {
    const header = {
        magic: offset.readU32(),
        cputype: offset.add(0x4).readU32(),
        cpusubtype: offset.add(0x8).readU32(),
        filetype: offset.add(0x0c).readU32(),
        ncmds: offset.add(0x10).readU32(),
        sizeofcmds: offset.add(0x14).readU32(),
        flags: offset.add(0x18).readU32()
    };
    if (header.cputype === 0x0100000c) {
        // arm64
        return header;
    }
    if (header.cputype === 0x01000007) {
        // x86-64
        return header;
    }
    throw new Error('Only support for 64-bit apps');
}

export function _isMachoHeaderAtOffset(offset: NativePointer) {
    const cursor = trunc4k(offset);
    if (cursor.readU32() === 0xfeedfacf) {
        return true;
    }
    return false;
}

export function getSections(segment: Segment): Section[] {
    const { name, slide } = segment;
    let { nsects, sectionsPtr } = segment;
    const sects = [] as Section[];
    while (nsects--) {
        sects.push({
            name: `${name}.${sectionsPtr.readUtf8String()}`,
            vmaddr: sectionsPtr.add(32).readPointer().add(slide),
            vmsize: sectionsPtr.add(40).readPointer()
        });
        sectionsPtr = sectionsPtr.add(80);
    }
    return sects;
}

export function getSegments(baseAddr: NativePointer, ncmds: number): Segment[] {
    const LC_SEGMENT_64 = 0x19;
    let cursor = baseAddr.add(0x20);
    const segments : Segment[] = [];
    let slide = ptr(0);
    while (ncmds-- > 0) {
        const command = cursor.readU32();
        const cmdSize = cursor.add(4).readU32();
        if (command !== LC_SEGMENT_64) {
            cursor = cursor.add(cmdSize);
            continue;
        }
        const segment = {
            name: cursor.add(0x8).readUtf8String(),
            vmaddr: cursor.add(0x18).readPointer(),
            vmsize: cursor.add(0x18).add(8).readPointer(),
            nsects: cursor.add(64).readU32(),
            sectionsPtr: cursor.add(72),
            slide: ptr(0x0)
        } as Segment;
        if (segment.name === '__TEXT') {
            slide = baseAddr.sub(segment.vmaddr);
        }
        cursor = cursor.add(cmdSize);
        segments.push(segment);
    }
    segments
        .filter(seg => seg.name !== '__PAGEZERO')
        .forEach((seg) => {
            seg.vmaddr = seg.vmaddr.add(slide);
            seg.slide = slide;
        });
    return segments;
}

export function loadFrameworkBundle(args: string[]): boolean {
    if (!ObjCAvailable) {
        console.log('dlf: This command requires the objc runtime');
        return false;
    }
    const path = args[0];
    const appPath = ObjC.classes.NSBundle.mainBundle().bundlePath();
    const fullPath = appPath.stringByAppendingPathComponent_(path);
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(fullPath);
    if (bundle.isLoaded()) {
        console.log('Bundle already loaded');
        return false;
    }
    return bundle.load();
}

export function unloadFrameworkBundle(args: string[]): boolean {
    if (!ObjCAvailable) {
        console.log('dlf: This command requires the objc runtime');
        return false;
    }
    const path = args[0];
    const appPath = ObjC.classes.NSBundle.mainBundle().bundlePath();
    const fullPath = appPath.stringByAppendingPathComponent_(path);
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(fullPath);
    if (!bundle.isLoaded()) {
        console.log('Bundle already unloaded');
        return false;
    }
    return bundle.unload();
}


export class IOSPathTransform extends PathTransform {
    _api: any | null;

    constructor() {
        super();
        this._api = null;
        this._fillVirtualDirs();
    }

    _fillVirtualDirs(): void {
        if (!hasMainLoop()) {
          return;
	    }
        const pool = this.api.NSAutoreleasePool.alloc().init();
        const appHome: string = new ObjC.Object(this.api.NSHomeDirectory()).toString();
        const appBundle: string = this.api.NSBundle.mainBundle().bundlePath().toString();
        const root = new VirtualEnt('/');
        root.addSub(new VirtualEnt("AppHome", appHome));
        root.addSub(new VirtualEnt("AppBundle", appBundle));
        const groupNames = this._getAppGroupNames();
        if (groupNames.length > 0) {
            const fileManager = this.api.NSFileManager.defaultManager();
            const appGroups = new VirtualEnt('AppGroups');
            root.addSub(appGroups);
            for (const groupName of groupNames) {
                const groupUrl = fileManager.containerURLForSecurityApplicationGroupIdentifier_(groupName);
                if (groupUrl !== null) {
                    appGroups.addSub(new VirtualEnt(groupName, groupUrl.path().toString()));
                }
            }
        }
        root.addSub(new VirtualEnt("Device", "/"));
        flatify(this._virtualDirs, root);
        this._mappedPrefixes = Object.keys(this._virtualDirs)
            .filter(key => typeof this._virtualDirs[key] === 'string')
            .sort((x, y) => x.length - y.length);
        pool.release();
    }

    _getAppGroupNames(): string[] {
        const task = this.api.SecTaskCreateFromSelf(NULL);
        if (task.isNull()) {
            return [];
        }
        const key = this.api.NSString.stringWithString_('com.apple.security.application-groups');
        const ids = this.api.SecTaskCopyValueForEntitlement(task, key, NULL);
        if (ids.isNull()) {
            return [];
        }
        const idsObj = new ObjC.Object(ids).autorelease();
        const names: string[] = nsArrayMap(idsObj, (group: any) => {
            return group.toString();
        });
        return names;
    }

    get api() {
        if (this._api === null) {
            this._api = {
                NSAutoreleasePool: ObjC.classes.NSAutoreleasePool,
                NSBundle: ObjC.classes.NSBundle,
                NSFileManager: ObjC.classes.NSFileManager,
                NSHomeDirectory: new NativeFunction(getGlobalExportByName('NSHomeDirectory')!, 'pointer', []),
                NSString: ObjC.classes.NSString,
                SecTaskCreateFromSelf: new NativeFunction(getGlobalExportByName('SecTaskCreateFromSelf')!, 'pointer', ['pointer']),
                SecTaskCopyValueForEntitlement: new NativeFunction(getGlobalExportByName('SecTaskCopyValueForEntitlement')!, 'pointer', ['pointer', 'pointer', 'pointer']),
                CFRelease: new NativeFunction(getGlobalExportByName('CFRelease')!, 'void', ['pointer'])
            };
        }
        return this._api;
    }
}

interface Segment {
    name: string;
    vmaddr: NativePointer;
    vmsize: NativePointer;
    nsects: number;
    sectionsPtr: NativePointer;
    slide: NativePointer;
}

interface Section {
    name: string;
    vmaddr: NativePointer;
    vmsize: NativePointer;
}
