/**
 * Password change form validation code
 *
 * @author Alan Frost
 *
 * Copyright (c) 207 Alan Frost
 */

  document.addEventListener("DOMContentLoaded", function() {
    var checkForm = function(e)
    {
      if(!checkUsername(this.username.value)) {
        alert("Error: Username must contain only letters, numbers, dashes and underscores and be 4-32 characters long.");
        this.username.focus();
        e.preventDefault();
        return;
      }
      if(this.password.value != "" && this.password.value == this.confirm.value) {
        if(!checkPassword(this.password.value)) {
          alert("The password you have entered is not valid.");
          this.password.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("Error: Please check that you've entered and confirmed your password.");
        this.password.focus();
        e.preventDefault();
        return;
      }
    };

    var change_password = document.getElementById("change_password");
    change_password.addEventListener("submit", checkForm, true);

    // HTML5 form validation

    var supports_input_validity = function()
    {
      var i = document.createElement("input");
      return "setCustomValidity" in i;
    }

    if(supports_input_validity()) {
      var usernameInput = document.getElementById("field_username");
      usernameInput.setCustomValidity(usernameInput.title);

      var passwordInput = document.getElementById("field_password");
      passwordInput.setCustomValidity(passwordInput.title);

      var confirmInput = document.getElementById("field_confirm");

      // input key handlers

      usernameInput.addEventListener("keyup", function(e) {
        usernameInput.setCustomValidity(this.validity.patternMismatch ? usernameInput.title : "");
      }, false);

      passwordInput.addEventListener("keyup", function(e) {
        this.setCustomValidity(this.validity.patternMismatch ? passwordInput.title : "");
        if(this.checkValidity()) {
          confirmInput.pattern = RegExp.escape(this.value);
          confirmInput.setCustomValidity(confirmInput.title);
        } else {
          confirmInput.pattern = this.pattern;
          confirmInput.setCustomValidity("");
        }
      }, false);

      confirmInput.addEventListener("keyup", function(e) {
        this.setCustomValidity(this.validity.patternMismatch ? confirmInput.title : "");
      }, false);

    }

  }, false);
