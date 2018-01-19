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

// Delete selected row(s) from the table
function deleteRow() {
  let selectedRows = $("#safebox-table").tabulator("getSelectedRows");
  selectedRows.forEach(function(row){
    row.delete();
  });
}

// Export selected row(s) from the table
function exportRows() {
  let rows = $("#safebox-table").tabulator("getSelectedRows");
  // If no rows are selected then get all currently displayed rows
  if (rows.length === 0) {
    rows = $("#safebox-table").tabulator("getRows", true);
  }
  let items = [];
  rows.forEach(function(row){
    items.push(row.getData());
  });
  return items;
}

// Import rows to table
function importRows() {
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
  $("#safebox-table").tabulator({columns:box.columns, data:box.contents, selectable:true});
  //$("#safebox-table").tabulator("setData", box.contents);
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
        box.columns = [
            {"title": "Account", "field": "account", "sorter": "string", "editor": "input"},
            {"title": "User Name", "field": "username", "sorter": "string", "editor": "input"},
            {"title": "Password", "field": "password", "sorter": "string", "editor": "input"}]
        box.contents = JSON.parse(plaintext);
        ($("#vkey").val(key));
        buildTable(box);

        let div = document.createElement('div');
        div.className = 'row';
        div.style.margin = "12px";
        div.id = 'safebox-buttons';

        let button = document.createElement('button');
        button.id = 'close-vault';
        button.className = "btn btn-primary";
        button.style.margin = "12px";
        let icon = document.createElement("I");
        icon.className = "fa fa-close";
        icon.setAttribute('aria-hidden', 'true');
        button.appendChild(icon);
        button.appendChild(document.createTextNode("  Close"));
        button.setAttribute('onclick', 'closeTable()');
        div.appendChild(button);

        button = document.createElement('button');
        button.id = 'save-vault';
        button.className = "btn btn-primary";
        button.style.margin = "12px";
        icon = document.createElement("I");
        icon.className = "fa fa-download";
        icon.setAttribute('aria-hidden', 'true');
        button.appendChild(icon);
        button.appendChild(document.createTextNode("  Save"));
        button.setAttribute('onclick', 'saveTable()');
        div.appendChild(button);

        button = document.createElement('button');
        button.id = 'add-vault';
        button.className = "btn btn-primary";
        button.style.margin = "12px";
        icon = document.createElement("I");
        icon.className = "fa fa-plus";
        icon.setAttribute('aria-hidden', 'true');
        button.appendChild(icon);
        button.appendChild(document.createTextNode("  Add"));
        button.setAttribute('onclick', '$("#safebox-table").tabulator("addRow",{})');
        div.appendChild(button);

        button = document.createElement('button');
        button.id = 'del-vault';
        button.className = "btn btn-primary";
        button.style.margin = "12px";
        icon = document.createElement("I");
        icon.className = "fa fa-minus";
        icon.setAttribute('aria-hidden', 'true');
        button.appendChild(icon);
        button.appendChild(document.createTextNode("  Delete"));
        button.setAttribute('onclick', 'deleteRow()');
        div.appendChild(button);

        button = document.createElement('button');
        button.id = 'import-vault';
        button.className = "btn btn-primary";
        button.style.margin = "12px";
        icon = document.createElement("I");
        icon.className = "fa fa-upload";
        icon.setAttribute('aria-hidden', 'true');
        button.appendChild(icon);
        button.appendChild(document.createTextNode("  Import"));
        button.setAttribute('onclick', 'importRows()');
        div.appendChild(button);

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
