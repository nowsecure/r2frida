module.exports = {
  sanitizeString
};

function sanitizeString (str) {
  const specialChars = '/\\`+-${}~|*,;:\"\'#@&<> ()[]!?%';
  return str.split('').map(c => specialChars.indexOf(c) === -1 ? c : '_').join('');
}
