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

function buildTable(contents) {
  // Create the table and add heading row
  var table = document.createElement("table");
  var tr = table.insertRow(-1);

  // Build the header using keys extracted from the data
  var col = [];
  for (var i = 0; i < contents.length; i++) {
    for (var key in contents[i]) {
      if (col.indexOf(key) === -1) {
        col.push(key);
      }
    }
  }

  for (var i = 0; i < col.length; i++) {
      var th = document.createElement("th");
      th.innerHTML = col[i];
      tr.appendChild(th);
  }

  // Add JSON data to the table as rows
  for (var i = 0; i < contents.length; i++) {
    tr = table.insertRow(-1);
    for (var j = 0; j < col.length; j++) {
      var tabCell = tr.insertCell(-1);
      tabCell.innerHTML = contents[i][col[j]];
    }
  }

  var divContainer = document.getElementById("vault");
  divContainer.innerHTML = "";
  divContainer.appendChild(table);
}

// View the vault or box contents
function viewVault() {
  console.log("viewVault");
  var mcf = document.getElementById("mcf");
  var contents = document.getElementById("contents");
  var mcf = deriveKey($("#vpassword").val(), mcf);
  console.log(mcf)
  var fields = mcf.split("$");
  if (contents && fields.length > 4 && fields[1] === "pbkdf2") {
    var key = forge.util.decode64(fields[4]);
    var plaintext = decryptAESGCM(key, contents);
    box = JSON.parse(plaintext);
    buildTable(box);
    var ciphertext = encryptAESGCM(key, "secrets in my vault");
    console.log(ciphertext)
    console.log(decryptAESGCM(key, ciphertext));
    //document.getElementById("vault").value = decryptAESGCM(key, ciphertext);
  }
}
