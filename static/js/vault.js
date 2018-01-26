/**
 * Vault management code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017-2018 Alan Frost
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
  $('.modal-content').keypress(function(event){
    var char = event.which || event.keyCode;
    if (char === 13) {
       $("#accessVault").modal("hide");
       event.preventDefault();
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
  var csrftoken = $('meta[name=csrf-token]').attr('content')
  console.log(csrftoken)
  const mytable = document.getElementById("safebox-table")
  if (mytable === null) {
    console.log('Missing safebox-table element');
  }
  const data = $("#safebox-table").tabulator("getData");
  const key = ($("#vkey").val());
  var ciphertext = encryptAESGCM(key, JSON.stringify(data));
  const boxName = ($("#vbox").val());
  document.getElementById(boxName + "-contents").innerText = ciphertext;

  update = '{"' + boxName + '":"' + ciphertext + '"}'
  let xhr = new XMLHttpRequest();
  xhr.open('patch', 'http://localhost:8080/vault', true);
  xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
  xhr.setRequestHeader('X-CSRFToken', csrftoken);

  // Callback to display success or error after POST request is complete
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        console.log('Safebox saved');
      } else {
        var json = JSON.parse(xhr.responseText);
        console.log(json.error);
      }
    }
  };

  // Send the encrypted safebox data as JSON
  xhr.send(update);
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
function importData(filelist) {
  //Retrieve the first (and only!) File from the FileList object
  if (filelist) {
    var file = filelist[0]; 
    if (file) {
      var reader = new FileReader();
      reader.onload = function(e) { 
        let csvdata = e.target.result;
        console.log( "Read " + file.name + " " + file.size + " bytes");
        let data = csvToJSON(csvdata);
        $("#safebox-table").tabulator("addData", data);
      }
      reader.readAsText(file);
    } else { 
      console.log("Failed to read file");
    }
  }
}

// Create a new vault
function createVault() {
  // Post dialog to get column headings
  columns = [{"field": "account", "sorter": "string", "title": "Account"},
             {"field": "username", "sorter": "string", "title": "User Name"},
             {"field": "password", "sorter": "string", "title": "Password"},
             {"field": "notes", "sorter": "string", "title": "Notes"}]
    // Create the tabulator, define the columns
  const mytable = document.getElementById("safebox-table")
  if (mytable === null) {
    let div =  document.createElement('div');
    div.id = 'safebox-table'
    let boxrow = document.getElementById('safebox-row')
    let boxlist = document.getElementById('safebox-list')
    boxrow.insertBefore(div, boxlist)
  }
  $("#safebox-table").tabulator({columns:columns, selectable:true});
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
      let key = forge.util.decode64(fields[4]);
      try {
        var plaintext = decryptAESGCM(key, ciphertext);
        var box = {}
        const columns = document.getElementById(boxName + "-columns").innerText;
        box.columns = JSON.parse(columns)
        box.contents = JSON.parse(plaintext);
        ($("#vkey").val(key));

        // Remove old table if shown
        const mytable = document.getElementById("safebox-table")
        if (mytable !== null) {
          $("#safebox-table").tabulator("clearData");
          mytable.parentElement.removeChild(mytable);
        }
        buildTable(box);

        let div = document.getElementById('safebox-buttons');
        if (div === null) {
          div = document.createElement('div');
          div.className = 'row';
          div.style.margin = "12px";
          div.id = 'safebox-buttons';

          let button = makeButton('close-vault', 'fa-close', 'Close', 'closeTable()');
          div.appendChild(button);

          button = makeButton('save-vault', 'fa-download', 'Save', 'saveTable()');
          div.appendChild(button);

          button = makeButton('add-vault', 'fa-plus', 'Add', '$("#safebox-table").tabulator("addRow",{})');
          div.appendChild(button);

          button = makeButton('del-vault', 'fa-minus', 'Delete', 'deleteRow()');
          div.appendChild(button);

          button = makeButton('import-vault', 'fa-upload', 'Import', null);
          button.addEventListener("click", function (e) {
          fileSelect = document.getElementById("fileSelect");
            if (fileSelect) {
              fileSelect.click();
            }
            e.preventDefault(); // prevent navigation to "#"
          }, false);
          div.appendChild(button);
          fileselector = document.createElement('input');
          fileselector.id = 'fileSelect';
          fileselector.type = 'file';
          fileselector.style = 'display:none';
          fileselector.accept = 'text/csv';
          fileselector.setAttribute('onchange', 'importData(this.files)');
          div.appendChild(fileselector);

          document.body.appendChild(div);
        }
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
