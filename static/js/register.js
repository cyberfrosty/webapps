/**
 * User registration form validation code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017 Alan Frost
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
      this.password.value = hashPassword(this.username.value, this.password.value);
      this.confirm.value = this.password.value;
      return;
    };

    var register_form = document.getElementById("register_form");
    register_form.addEventListener("submit", checkForm, true);

    // HTML5 form validation

    var supports_input_validity = function()
    {
      var i = document.createElement("input");
      return "setCustomValidity" in i;
    }

    if(supports_input_validity()) {
      var usernameInput = document.getElementById("username");
      usernameInput.setCustomValidity(usernameInput.title);

      var passwordInput = document.getElementById("password");
      passwordInput.setCustomValidity(passwordInput.title);

      var confirmInput = document.getElementById("confirm");

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
