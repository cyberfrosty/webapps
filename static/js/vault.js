/**
 * Vault management code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017 Alan Frost
 */

document.addEventListener("DOMContentLoaded", function() {

  // Toggle checked symbol in safe box list
  var list = document.getElementById("vaultList"");
  list.addEventListener('click', function(ev) {
    if (ev.target.tagName === 'LI') {
      ev.target.classList.toggle('checked');
    }
  }, false);

}, false);

function viewVault() {
  console.log("viewVault");
  console.log(hashword("yuki", "madman"));
  var mcf = deriveKey($("#vpassword").val());
  var fields = mcf.split("$");
  if (fields.length > 4 && fields[1] === "pbkdf2") {
    var key = forge.util.decode64(fields[4]);
    var ciphertext = encryptAESGCM(key, "secrets in my vault");
    console.log(decryptAESGCM(key, ciphertext));
    document.getElementById("vault").value = decryptAESGCM(key, ciphertext);
  }
}
