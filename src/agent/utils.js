module.exports = {
  flagify
};

function flagify (s) {
  return s.replace(/[\s-\/\\()\[\]<>!?$;%@`|&"+,]/g, '_');
}
