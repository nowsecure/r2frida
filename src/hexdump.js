// Hexdump Initializer
var Hexdump = function (data, options) {
  var self = this;
  self.hexdump = [];
  if (!options) {
    options = {};
  }
  self.options = {
    offset: options.offset || 0,
    width: options.width || 16,
    spacing: options.spacing || 0,
    ascii: options.ascii || false,
    hexNull: options.hexNull || '  ',
    stringNull: options.stringNull || ' ',
    left: options.left || '|',
    right: options.right || '|'
  };

  if (!data) {
    return;
  }
  // Make sure spacing is within proper range.
  if (self.options.spacing > data.length) {
    self.options.spacing = data.length;
  }

  // Make sure width is within proper range.
  if (self.options.width > data.length) {
    self.options.width = data.length;
  }

  self.output = this.dump(data);
};

Hexdump.prototype.toString = function () {
  return this.output;
};

Hexdump.prototype.dump = function (data) {
  var self = this;

  function Offset (num, pad) {
    var offset = num.toString(16);
    if (offset.length < 8) {
      offset = '0x' + Array(8 - offset.length + 1).join('0') + offset;
    } else {
      offset = '0x' + offset;
    }
    return offset;
  }

  self.output = '';
  for (var i = 0; i < data.length; i += self.options.width) {
    var offset = Offset(self.options.offset + i, 8);

    self.output += offset + ' '; // 0x00000000

    var spacingCount = 0;
    var width = Math.min(self.options.width, data.length - i);
    for (var x = 0; x < width; x++) {
      var ch = data[i + x].toString(16);
      if (ch.length === 1) {
        ch = '0' + ch;
      }
      if (spacingCount === self.options.spacing) {
        self.output += ch + ' ';
        spacingCount = 0;
      } else {
        self.output += ' ';
        spacingCount++;
      }
    }
    if (width !== self.options.width) {
      var wx = self.options.width - width;
      wx *= 3;
      wx += 1;
      self.output += Array(wx).join(' ');
    }

    self.appendString(data.slice(i, i + self.options.width));
    self.output += '\n';
  }
  return self.output;

/*
    var hexdump_container = document.getElementById(this.options.container);
    hexdump_container.innerHTML = this.output;
*/
};

Hexdump.prototype.appendString = function (data) {
  var self = this;
  data = data.toString();
  var str = data.replace(/[^a-zA-Z0-9 -]/g, '.');
  if (str.length < 16) {
    str += Array(16 - str.length + 1).join('.');
  }
  self.output += ' ' + self.options.left + str + self.options.right;
};

Hexdump.prototype.process = function (data) {
  const self = this;

  var hexArray = [];
  for (let i = 0; i < data.length; i++) {
    hexArray.push(toHex(data[i]));
  }

  if (hexArray.length < self.options.width) {
    var amount = self.options.width - hexArray.length;
    for (let i = 0; i < amount; i++) {
      hexArray.push(self.options.hexNull);
    }
  }

  data = data.toString();
  if (data.length < self.options.width) {
    var stringAmount = self.options.width - data.length;
    for (var i = 0; i < stringAmount; i++) {
      data += self.options.stringNull;
    }
  }

  return {
    data: hexArray,
    string: data
  };
};

function toHex (characters) {
  for (var i = 0; i < characters.length; i++) {
    var r = characters.charCodeAt(i).toString(16);
    // var r = characters[i].toString(16);
    r = characters[i].charCodeAt(0).toString(16);
    if (r.length < 2) {
      return '0' + r;
    } else {
      return r;
    }
  }
}

exports.Hexdump = Hexdump;
