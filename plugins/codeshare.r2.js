var codeShareRegisterPlugin = (function() {
	const url = "https://codeshare.frida.re";
	const version = "0.1.0";
	const author = "pancake";

	const projects = new Set();
	const results = new Set();
	function codeShareSearch(word) {
		if (projects.size > 0) {
			for (const line of projects.values()) {
				if (line.indexOf(word) !== -1) {
					console.log(line);
				}
			}
			return;
		}
		var pages = 2; // TODO: pull last page from main page
		const wheel = "|/-\\";
		for (var page = 1; page < pages; page++) {
			const ch = wheel[page%wheel.length];
			const res = r2.syscmds("curl -s '" + url + "/browse?page=" + page + "'").trim();
			const hits = results.size;
			const count = projects.size;
			write("\r["+ch+"] Caching page " + page + "/" + pages + " ("+hits+"/"+count+")\r[");
			flush();
			if (res === "") {
				console.error ("Oops");
				break;
			}
			let lastPage = 1;
			for (const line of res.split("\n")) {
				const pageat = line.indexOf("?page=");
				if (pageat !== -1) {
					const pageNumber = Number.parseInt(line.slice(pageat + 6));
					if (pageNumber > lastPage) {
						lastPage = pageNumber;
					}
				}
				const at = line.indexOf("re/@");
				if (at !== -1) {
					const line2 = line.slice(at + 4)
					const to = line2.indexOf("/\"");
					if (to !== -1) {
						const line3 = line2.slice(0, to);
						projects.add(line3);
						if (line3.indexOf(word) !== -1) {
							results.add(line3);
						}
					}
				}
			}
			if (lastPage > pages) {
				pages = lastPage;
			}
		}
		write("\r");
		flush();

		for (const line of results.values()) {
			console.log(line);
		}
	}

	function codeShareDescribe(path) {
		const res = r2.syscmds("curl -s " + url + "/api/project/" + path + ".js");
		const obj = JSON.parse(res);
		const r = [
			"Name: " + obj.project_name,
			"Description: " + obj.description,
			"Frida: " + obj.frida_version
		];
		// return JSON.stringify (JSON.parse(res), null, 2);
		return r.join("\n");;
	}

	function codeShareCat(path) {
		const res = r2.syscmds("curl -s " + url + "/api/project/" + path + ".js");
		return JSON.parse(res).source;
	}

	function codeShareInject(path) {
		if (!inFrida ()) {
			console.error ("Use r2 frida://");
			return;
		}

		const res = r2.syscmd("curl -s " + url + "/api/project/" + path + ".js | jq .source > .script.r2frida.js");
		// TODO: check if file is > 0
		r2.cmd(":. .script.r2frida.js");
		r2.cmd("rm .script.r2frida.js");
		/*
		   const res = r2.syscmds("curl " + url + "/api/project/" + path + ".js");
		   console.log(res);
		   const source = JSON.parse(res).source;
		   const b64source = b64(source);
		   console.log(source);
		 */
	}
	function codeShareUsage() {
		console.log("Usage: codeshare [-flag] [..]");
		console.log("codeshare -s jail     # search for scripts containing 'jail'");
		console.log("codeshare -i foo/bar  # inject foo/bar script. requires r2frida session");
		console.log("codeshare -c foo/bar  # cat script");
		console.log("codeshare -d foo/bar  # describe script");
		console.log("codeshare -v          # show version");
	}
	function inFrida(path) {
		return r2.cmd("o").indexOf("frida://") !== -1;
	}
	function codeShare(path) {
		if (path.startsWith("-s")) {
			return codeShareSearch(path.slice(2).trim());
		} else if (path.startsWith("-i")) {
			return codeShareInject(path.slice(2).trim());
		} else if (path.startsWith("-d")) {
			return console.log(codeShareDescribe(path.slice(2).trim()));
		} else if (path.startsWith("-c")) {
			return console.log(codeShareCat(path.slice(2).trim()));
		} else if (path.startsWith("-v")) {
			return console.log(version);
		} else {
			return codeShareUsage ();
		}
	}
	function codeShareCommand(cmd) {
		const args = cmd.substr(9).trim();
		if (args.startsWith("-h") || args === "") {
			codeShareUsage();
		} else {
			codeShare(args);
		}
	}

	function main() {
		r2.unload('core', 'codeshare');
		r2.plugin('core', function () {
			function coreCall (cmd) {
				if (cmd.startsWith('codeshare')) {
					try {
						codeShareCommand(cmd);
					} catch (e) {
						console.error(e);
					}
					return true;
				}
				return false;
			}
			return {
				name: 'codeshare',
				author: author,
				license: 'MIT',
				desc: 'pull and run codeshare scripts via r2frida',
				call: coreCall
			};
		});
	}
	return main;
})();
codeShareRegisterPlugin();

