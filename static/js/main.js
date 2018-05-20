/**
 * Crypto and utility functions
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017-2018 Alan Frost
 */

// Define proto to strip beginning and ending quotes
String.prototype.unquoted = function (){return this.replace (/(^")|("$)/g, '')}

$(document).on('click',function() {
  $('.collapse').collapse('hide');
})

// Set input focus to search field in modal
$("body").on("shown.bs.modal", "#search", function (event) {
  $("input:visible:enabled:first", this).focus();
});

// Add an event listener function to an element for a list of events
function addEventListeners(element, eventList, listener) {
  for(event of eventList) {
    element.addEventListener(event, listener, false);
  }
}

// Add HTML5 form validation event listeners
function addHTML5FormValidation(form) {
  var supports_input_validity = function() {
    var i = document.createElement("input");
    return "setCustomValidity" in i;
  }
  if(supports_input_validity()) {
    // Add event listeners and validation to all input fields
    const eventList = ["change", "keyup", "paste", "input"];
    const inputList = document.querySelectorAll('input, select');
    for(let input of inputList) {
      // When invalid event fires add an error class for css highlight
      input.addEventListener('invalid', (event) => {
        input.classList.add('error');
      }, false);

      // Check validity on blur
      input.addEventListener('blur', (event) => {
        input.checkValidity();
      })
    
      // Input event handlers to remove error and check validity on events
      // Password confirm is handled differently to enforce match
      if(input.name === 'password') {
        const confirmInput = document.getElementById("confirm");
        addEventListeners(input, eventList, function(e) {
          input.classList.remove('error');
          input.setCustomValidity(input.validity.patternMismatch ? input.title : "");
          if(input.checkValidity()) {
            confirmInput.pattern = RegExp.escape(input.value);
            confirmInput.setCustomValidity(confirmInput.title);
          } else { // Set the password confirm pattern to be the new password to ensure they match
            confirmInput.pattern = input.pattern;
            confirmInput.setCustomValidity("");
          }
        });
      } else {
        addEventListeners(input, eventList, function(e) {
          input.classList.remove('error');
          input.setCustomValidity(input.validity.patternMismatch ? input.title : "");
        });
      }
    }
  }
}

// Initialize search list
function searchInit() {
  var i;
  const ul = document.getElementById("searchList");
  const li = ul.getElementsByTagName('li');

  // Loop through all list items, and hide until the user initiates a search
  for (i = 0; i < li.length; i++) {
    li[i].style.display = "none";
  }
}

// Modal search dialog event handler
function searchList(event) {
  const char = event.which || event.keyCode;
  const input = document.getElementById('searchPhrase');
  const filter = input.value.toUpperCase();
  let displayed = 0;
  const max_shown = 10; // Never show more than 10 items in dropdown
  if (char === 13) {
    $("#search").modal("hide");
    if (filter.length > 0) {
      const params = '?query=' + encodeURIComponent(filter.trim());
      const href = window.location.protocol + '//' + window.location.host + '/search'
      window.location.assign(href + params);
    }
  }
  else {
    var a, i, j;
    const ul = document.getElementById("searchList");
    const li = ul.getElementsByTagName('li');

    // Loop through all list items, and hide those who don't match the search query
    for (i = 0; i < li.length; i++) {
      let matched = false;
      if (displayed < max_shown && filter && filter.length > 0) {
        a = li[i].getElementsByTagName("a")[0];
        const words = a.innerText.toUpperCase().split(' ');
        for(j = 0; j < words.length; j++){
          if (words[j].startsWith(filter)) {
            matched = true;
            break;
          }
        }
      }
      if (matched) {
        li[i].style.display = "";
        displayed = displayed + 1;
      } else {
        li[i].style.display = "none";
      }
    }
  }
}

// JavaScript form validation utilities

// polyfill for RegExp.escape
if(!RegExp.escape) {
  RegExp.escape = function(s) {
    return String(s).replace(/[\\^$*+?.()|[\]{}]/g, '\\$&');
  };
}

function checkPassword(password) {
  var re = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,32}$/;
  return re.test(password);
};

function checkName(name) {
  if(name.length < 2 || name.length > 32) {
    return false;
  }
  else {
    const temp = document.createElement('div');
    temp.innerHTML = name;
    console.log(temp.innerText);
    return temp.innerText == name;
  }
}

function checkUsername(username) {
  var re = /^([a-zA-Z0-9_-]){4,32}$/;
  return re.test(username);
}

function checkEmail(email) {
  var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(email);
}

/**
 * Check a phone number to see if it is probably ok by stripping spaces, dashes and parens then
 * checking US numbers for 10 digits and requiring a country code for all others.
 *
 * @param {string} CSV phone number
 */
function checkPhone(phone) {
  phone = phone.replace(/[ \-\(\)]/g, '');
  var re = /^(\d{10})$/;
  if(phone.startsWith('+')) {
    if(phone.startsWith('+1')) {
      re = /^\+(\d{11})$/;
    } else {
      re = /^\+(\d{8,24})$/;
    }
  }
  return re.test(phone);
}

/**
 * Convert CSV data with headers to JSON array
 *
 * @param {string} CSV input data
 */
function csvToJSON(csv){
  var lines=csv.split("\n");
  var items = [];
  var headers=lines[0].split(",");
  for(var i=1;i<lines.length;i++){
    var obj = {};
    var currentline=lines[i].split(",");

    for(var j=0;j<headers.length;j++){
      obj[headers[j]] = currentline[j];
    }
    items.push(obj);
  }
  return items
}

/**
 * Convert JSON object or JSON string to CSV
 *
 * @param {object|string} JSON input data
 */
function jsonToCSV(data) {     
  var arrData = typeof data != 'object' ? JSON.parse(data) : data;
  var csv = '';    
  var row = '';

  // Extract column labels
  for (var index in arrData[0]) {
      row += index + ',';
  }
  row = row.slice(0, -1);
  csv += row + '\n';

  for (var i = 0; i < arrData.length; i++) {
    row = '';
    for (var index in arrData[i]) {
      row += '"' + arrData[i][index] + '",';
    }
    row.slice(0, row.length - 1);
    csv += row + '\n';
  }
  return csv;
}   

/**
 * Make a button
 *
 * @param {string} id
 * @param {string} Font Awsome icon to use in button
 * @param {string} display text
 * @param {func} onclick function
 */
function makeButton(id, faIcon, text, clickFunc) {
  let button = document.createElement('button');
  button.id = id;
  button.className = "btn btn-primary";
  button.style.margin = "12px";
  if (faIcon) {
    let icon = document.createElement('i');
    icon.className = "fa " + faIcon;
    icon.setAttribute('aria-hidden', 'true');
    button.appendChild(icon);
  }
  button.appendChild(document.createTextNode("  " + text));
  if (clickFunc) {
    button.setAttribute('onclick', clickFunc);
  }
  return button;
}

//this trick will generate a temp "a" tag
//var link = document.createElement("a");    
//link.id="lnkDwnldLnk";

//this part will append the anchor tag and remove it after automatic click
//document.body.appendChild(link);

//var csv = CSV;  
//blob = new Blob([csv], { type: 'text/csv' }); 
//var csvUrl = window.webkitURL.createObjectURL(blob);
//var filename = 'UserExport.csv';
//$("#lnkDwnldLnk")
//.attr({
//    'download': filename,
//    'href': csvUrl
//}); 

//$('#lnkDwnldLnk')[0].click();    
//document.body.removeChild(link);
//}

/**
 * Use HMAC SHA256 to create unique hashed password before sending to server to prevent a MitM
 * from seeing * the user's password and also so that the server never has the actual password
 * either. The server then uses PBKDF2 or SCRYPT to hash this for storage.
 *
 * @param {string} username
 * @param {string} password
 * @return {string} hex digest
 */
function hashPassword(username, password) {
  var hmac = forge.hmac.create();
  hmac.start("sha256", username);
  hmac.update(password);
  return hmac.digest().toHex();
}

/**
 * Derive a 256 bit key from the user password, and optionally validate the password.
 * Using PBKDF2 (Password-Based Key Derivation Function2, PKCS #5 v2.0).
 * Accepts MCF format $pbkdf2$iterations$salt$keydata
 *
 * @param {string} password
 * @param {string} MCF formatted current value, (optional) or empty to create initial
 * @return {string} MCF formatted current value
 */
function deriveKey(password, mcf) {
  var count = 2000;
  var salt;
  var key;
 
  if (password === undefined || password.length < 2) {
    var error = new Error("Invalid password");
    throw error;
  }
  // Generate a new key
  if (mcf === undefined || mcf.length === 0) {
    // generate a random salt
    salt = forge.random.getBytesSync(16);
    key = forge.pkcs5.pbkdf2(password, salt, count, 32, "sha256");
  } else if (mcf.length > 10 && mcf[0] === "$") {
    // Validate an exiting key in MCF format ("$pbkdf2$1000$$")
    var fields = mcf.split("$");
    if (fields.length > 4 && fields[1] === "pbkdf2") {
      count = fields[2];
      salt = forge.util.decode64(fields[3]);
      key = forge.pkcs5.pbkdf2(password, salt, count, 32, "sha256");
      var hashval = forge.util.encode64(key);
      if (fields[4].length > 32 && hashval != fields[4]) {
        throw new Error("Password match failed");
      }
    } else {
      throw new Error("Invalid MCF argument");
    }
  } else {
    throw new Error("Invalid MCF argument");
  }
  return "$pbkdf2$" + count + "$" + forge.util.encode64(salt) + "$" + forge.util.encode64(key);
}

/**
 * XOR 2 keys to create a new derived key
 *
 * @param {string} key1
 * @param {string} key2
 * @param {integer} key length
 * @return {string} derived key
 */
function xorKeys(key1, key2, klen) {
  return forge.util.xorBytes(key1, key2, klen);
}

/**
 * Encrypt bytes with AES key using GCM mode
 * @param {string} key
 * @param {string} plaintext
 * @param {string} additional authenticated data (optional)
 * @return {string} ciphertext as base64 string with iv:ciphertext:tag
 */
function encryptAESGCM(key, plaintext, aad) {
  var cipher = forge.cipher.createCipher("AES-GCM", key);
  var iv = forge.random.getBytesSync(12);
  cipher.start({
    iv: iv,
    aad: aad,
    tagLength: 128
  });
  cipher.update(forge.util.createBuffer(plaintext));
  cipher.finish();
  var encrypted = iv + cipher.output.data + cipher.mode.tag.data;
  return forge.util.encode64(encrypted);
}

/**
 * Decrypt bytes with AES key using GCM mode
 * @param {string} key
 * @param {string} cipherext as base64 string with iv:ciphertext:tag
 * @param {string} additional authenticated data (optional)
 * @return {string} plaintext as string
 */
function decryptAESGCM(key, ciphertext, aad) {
  ciphertext = forge.util.decode64(ciphertext);
  var decipher = forge.cipher.createDecipher("AES-GCM", key);
  var iv = ciphertext.slice(0, 12);
  var tag = ciphertext.slice(-16);
  decipher.start({
    iv: iv,
    aad: aad,
    tag: tag
  });
  decipher.update(forge.util.createBuffer(ciphertext.slice(12, -16)));
  var pass = decipher.finish();
  if (pass) {
    return decipher.output.data;
  } else {
    console.log("decryption failed");
    throw new Error("Decrypt failed");
  }
}

function passworddone() { 
    document.getElementById("passwordpopup").style.display = "none";
    var password = document.getElementById("password").value;

    //DO STUFF WITH PASSWORD HERE
    
};

function getpassword() {
     document.getElementById("passwordpopup").style.display = "block";
}

