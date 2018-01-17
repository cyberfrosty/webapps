/**
 * Vault management code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017-2018 Alan Frost
 */

var vkey;

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
$("body").on("shown.bs.modal", "#accessVault", function (event) {
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
       $("#accessVault").modal("hide");
       e.preventDefault();
       accessVault();
       return false;
    }
  })
});

function closeTable() {
  ($("#vkey").val(''));
  const mytable = document.getElementById("safebox-table")
  if (mytable !== null) {
    $("#safebox-table").tabulator("clearData");
    mytable.parentElement.removeChild(mytable);
  }
  let btns = document.getElementById('safebox-buttons');
  if (btns !== null) {
    document.body.removeChild(btns);
  }
}

function saveTable() {
  const mytable = document.getElementById("safebox-table")
  if (mytable === null) {
    console.log('Missing safebox-table element');
  }
  const data = $("#safebox-table").tabulator("getData");
  console.log(JSON.stringify(data));
  const key = ($("#vkey").val());
  var ciphertext = encryptAESGCM(key, JSON.stringify(data));
  console.log(ciphertext);
  const boxName = ($("#vbox").val());
  document.getElementById(boxName + "-contents").innerText = ciphertext;

  update = '{"' + boxName + '":"' + ciphertext + '"}'
  let xhr = new XMLHttpRequest();
  xhr.open('post', 'http://localhost:8080/api/update.vault', true);
  xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');

  // send the collected data as JSON
  xhr.send(update);

  xhr.onloadend = function () {
    // done
  };
}

function buildTable(box) {
  // Create the tabulator, define the columns
  const mytable = document.getElementById("safebox-table")
  if (mytable === null) {
    let div =  document.createElement('div');
    div.id = 'safebox-table'
    let boxrow = document.getElementById('safebox-row')
    let boxlist = document.getElementById('safebox-list')
    boxrow.insertBefore(div, boxlist)
  }
  $("#safebox-table").tabulator(box.columns);
  $("#safebox-table").tabulator("setData", box.contents);
}

// View the vault or box contents
function accessVault() {
  var errmsg = 'Unable to verify your credentials'
  var mcf = document.getElementById("mcf").innerHTML;
  console.log(mcf)
  try {
    mcf = deriveKey($("#vpassword").val(), mcf);
    const boxName = ($("#vbox").val());
    const contents = document.getElementById(boxName + "-contents").innerText;
    ciphertext = contents.unquoted();
    const fields = mcf.split("$");
    if (contents && fields.length > 4 && fields[1] === "pbkdf2") {
      var key = forge.util.decode64(fields[4]);
      vkey = key;
      try {
        var plaintext = decryptAESGCM(key, ciphertext);
        var box = {}
        box.columns = {
          columns:[
            {"title": "Account", "field": "account", "sorter": "string", "editor": "input"},
            {"title": "User Name", "field": "username", "sorter": "string", "editor": "input"},
            {"title": "Password", "field": "password", "sorter": "string", "editor": "input"}]}
        box.contents = JSON.parse(plaintext);
        ($("#vkey").val(key));
        buildTable(box);

        let div = document.createElement('div');
        div.className = 'row';
        div.style.margin = "12px";
        div.id = 'safebox-buttons';
        let close = document.createElement("BUTTON");
        close.id = 'close-vault';
        close.className = "btn btn-primary";
        close.style.margin = "12px";
        let icon = document.createElement("I");
        icon.className = "fa fa-close";
        icon.setAttribute('aria-hidden', 'true');
        close.appendChild(icon);
        close.appendChild(document.createTextNode("  Close"));
        close.setAttribute('onclick', 'closeTable()');
        div.appendChild(close);

        let save = document.createElement("BUTTON");
        save.id = 'save-vault';
        save.className = "btn btn-primary";
        save.style.margin = "12px";
        icon = document.createElement("I");
        icon.className = "fa fa-download";
        icon.setAttribute('aria-hidden', 'true');
        save.appendChild(icon);
        save.appendChild(document.createTextNode("  Save"));
        save.setAttribute('onclick', 'saveTable()');
        div.appendChild(save);
        document.body.appendChild(div);
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
