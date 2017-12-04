/**
 * Vault management code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017 Alan Frost
 */

document.addEventListener("DOMContentLoaded", function() {

  // Toggle checked symbol in safe box list
  var list = document.getElementById("vaultList");
  if (list) {
    list.addEventListener('click', function(ev) {
      if (ev.target.tagName === 'LI') {
        ev.target.classList.toggle('checked');
      }
    }, false);
  }
}, false);

// Set input focus to password field in modal
$("body").on("shown.bs.modal", "#viewVault", function () {
  $("input:visible:enabled:first", this).focus();
});

// Submit modal action when enter pressed
$(function(){
  $('.modal-content').keypress(function(e){
    if (e.which === 13) {
       $("#viewVault").modal("hide");
       e.preventDefault();
       viewVault();
       return false;
    }
  })
});

// View the vault or box contents
function viewVault() {
  console.log("viewVault");
  console.log(hashPassword("yuki", "madman"));
  var mcf = deriveKey($("#vpassword").val());
  console.log(mcf)
  var fields = mcf.split("$");
  if (fields.length > 4 && fields[1] === "pbkdf2") {
    var key = forge.util.decode64(fields[4]);
    var ciphertext = encryptAESGCM(key, "secrets in my vault");
    console.log(ciphertext)
    console.log(decryptAESGCM(key, ciphertext));
    document.getElementById("vault").value = decryptAESGCM(key, ciphertext);
  }
}
