var fs = require ('fs');
var nfd_in = +process.env.R2PIPE_IN;
var nfd_out = +process.env.R2PIPE_OUT;

if (!nfd_in || !nfd_out) {
  console.error ("This script needs to run from radare2 with r2pipe://");
  process.exit(1);
}

var fd_in = fs.createReadStream(null, {
  fd: nfd_in
});
var fd_out = fs.createWriteStream(null, {
  fd: nfd_out
});

console.log ("Running r2pipe io");

fd_in.on('end', function() {
  console.log ("--> THE END");
});

function writeObject(obj) {
  if (!obj) {
    obj = {};
  }
  //console.log ("Send Object To R2",obj);
  fd_out.write (JSON.stringify (obj) + "\x00");
}

function onObject(cb) {
  fd_in.on('data', function(data) {
    data = data.slice (0, -1);
    var obj_in = JSON.parse (data);
    if (cb) {
      cb (obj_in);
    }
    /*
    		console.log ("got data(", obj_in,")");
    		var obj = {result:obj_in.count, data:[1,2,3]};
    		writeObject (obj);
    */
  });
}

module.exports.writeObject = writeObject;
module.exports.onObject = onObject;
