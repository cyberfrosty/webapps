/**
 * Vault management code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017 Alan Frost
 */

document.addEventListener("DOMContentLoaded", function() {

  // Toggle checked symbol in safe box list
  let list = document.getElementById("vaultList");
  if (list) {
    list.addEventListener('click', function(ev) {
      if (ev.target.tagName === 'LI') {
        ev.target.classList.toggle('checked');
      }
    }, false);
  }
}, false);

// Set input focus to password field in modal and get the trigger
$("body").on("shown.bs.modal", "#viewVault", function (event) {
  $("input:visible:enabled:first", this).focus();
  const triggerElement = $(event.relatedTarget); // list-group-item that triggered the modal
  const trigger = triggerElement[0]
  const boxName = (('id' in trigger) ? trigger.id : '');

  // Set modal title to show selected box title and hidden field with box name
  const boxTitle = (('innerText' in trigger) ? trigger.innerText : 'Vault');
  let modal = $(this);
  modal.find('.modal-title').text('Unlock ' + boxTitle);
  modal.find("#vbox").val(boxName);
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

function buildTable(box) {
  // Create the tabulator, define the columns
  console.log(box['contents'])
  const mytable = document.getElementById("safebox-table")
  if (mytable === null) {
    console.log('Missing safebox-table element');
  }
  $("#safebox-table").tabulator(box.columns);
  $("#safebox-table").tabulator("setData", box.contents);
}

// View the vault or box contents
function viewVault() {
  var errmsg = 'Unable to verify your credentials'
  var mcf = document.getElementById("mcf").innerHTML;
  console.log(mcf)
  try {
    mcf = deriveKey($("#vpassword").val(), mcf);
    const boxName = ($("#vbox").val());
    const contents = document.getElementById(boxName + "-contents").innerText;
    console.log(contents);
    ciphertext = contents.unquoted();
    const fields = mcf.split("$");
    if (contents && fields.length > 4 && fields[1] === "pbkdf2") {
      var key = forge.util.decode64(fields[4]);
      try {
        var plaintext = decryptAESGCM(key, ciphertext);
        var box = {}
        box.columns = {
          columns:[
            {"title": "Account", "field": "account", "sorter": "string"},
            {"title": "User Name", "field": "username", "sorter": "string"},
            {"title": "Password", "field": "password", "sorter": "string"}]}
        box.contents = JSON.parse(plaintext);
        buildTable(box);
      }
      catch(err) {
        console.log(err)
      }
    }
  }
  catch(err) {
    console.log(err)
  }
}
