let tainted = document.location.search;
tainted.replace(/^\s+|\s+$/g, ''); // NOT OK - but not flagged
tainted.split(/ *, */); // NOT OK - but not flagged
tainted.replace(/\s*\n\s*/g, ' '); // NOT OK - but not flagged
tainted.split('\n'); // OK
tainted.replace(/.*[/\\]/, ''); // NOT OK - but not flagged
tainted.replace(/.*\./, ''); // NOT OK - but not flagged
tainted.replace(/^.*[/\\]/, ''); // OK
tainted.replace(/^.*\./, ''); // OK
tainted.replace(/^(`+)\s*([\s\S]*?[^`])\s*\1(?!`)/); // NOT OK - but not flagged
tainted.replace(/^(`+)([\s\S]*?[^`])\1(?!`)/); // OK
/^(.*,)+(.+)?$/.test(tainted); // NOT OK
tainted.match(/[0-9]*['a-z\u00A0-\u05FF\u0700-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]+|[\u0600-\u06FF\/]+(\s*?[\u0600-\u06FF]+){1,2}/i); // NOT OK - but not flagged
tainted.match(/[0-9]*['a-z\u00A0-\u05FF\u0700-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]{1,256}|[\u0600-\u06FF\/]{1,256}(\s*?[\u0600-\u06FF]{1,256}){1,2}/i); // OK
tainted.match(/^(\+|-)?(\d+|(\d*\.\d*))?(E|e)?([-+])?(\d+)?$/); // NOT OK - but not flagged
if (tainted.length < 7000) {
  tainted.match(/^(\+|-)?(\d+|(\d*\.\d*))?(E|e)?([-+])?(\d+)?$/); // OK
}
tainted.match(/<.*class="([^"]+)".*>/); // NOT OK - but not flagged
tainted.match(/<.*style="([^"]+)".*>/); // NOT OK - but not flagged
tainted.match(/<.*href="([^"]+)".*>/); // NOT OK - but not flagged
tainted.match(/^([a-z0-9-]+)[ \t]+([a-zA-Z0-9+\/]+[=]*)([\n \t]+([^\n]+))?$/); // NOT OK - but not flagged
tainted.match(/^([a-z0-9-]+)[ \t]+([a-zA-Z0-9+\/ \t\n]+[=]*)(.*)$/); // NOT OK - but not flagged
tainted.match(/^([a-z0-9-]+)[ \t]+([a-zA-Z0-9+\/]+[=]*)([ \t]+([^ \t][^\n]*[\n]*)?)?$/); // OK
tainted.match(/^([a-z0-9-]+)[ \t\n]+([a-zA-Z0-9+\/][a-zA-Z0-9+\/ \t\n=]*)([^a-zA-Z0-9+\/ \t\n=].*)?$/); // OK
tainted.match(/^(?:\.?[a-zA-Z_][a-zA-Z_0-9]*)+$/); // NOT OK - but not flagged
tainted.match(/^(?:\.?[a-zA-Z_][a-zA-Z_0-9]*)(?:\.[a-zA-Z_][a-zA-Z_0-9]*)*$/); // OK
tainted.match(/^([^-]+)-([A-Za-z0-9+/]+(?:=?=?))([?\x21-\x7E]*)$/); // NOT OK - but not flagged
tainted.match(/^([^-]+)-([A-Za-z0-9+/=]{44,88})(\?[\x21-\x7E]*)*$/); // OK - this is a bug fix for the above line, but it is now flagged for a different reason
/[a-z][A-Z]|[A-Z]{2,}[a-z]|[0-9][a-zA-Z]|[a-zA-Z][0-9]|[^a-zA-Z0-9 ]/.test(tainted); // NOT OK - but not flagged
/[a-z][A-Z]|[A-Z]{2}[a-z]|[0-9][a-zA-Z]|[a-zA-Z][0-9]|[^a-zA-Z0-9 ]/.test(tainted); // OK
