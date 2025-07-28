// run ':. tsexample.ts' inside an 'r2 frida://' session to load it
//
declare let r2frida: any;

async function hellow(args: string[]) : Promise<string> {
	return args.length > 0? args[0]: "Hellow";
}
const commands : any[any] = {
  hellow: hellow,
};

r2frida.pluginRegister('hellow', function (name: string) : any {
  return commands[name];
});
