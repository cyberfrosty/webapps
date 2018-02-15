/**
 * User registration form validation code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017-2018 Alan Frost
 */

  document.addEventListener("DOMContentLoaded", function() {
    var checkForm = function(e)
    {
      if(this.phone.value != "") {
        if(!checkPhone(this.phone.value)) {
          alert("US phone numbers must be 10 digits and all others must include +country code.");
          this.phone.focus();
          e.preventDefault();
          return;
        }
      }
      if(this.email.value != "") {
      if(!checkEmail(this.email.value)) {
        alert("Error: The email address you have entered is not valid.");
        this.email.focus();
        e.preventDefault();
        return;
      }
      if(this.user.value != "") {
        if(!checkName(this.user.value)) {
          alert("Names must be 2-32 characters in length with no symbols.");
          this.user.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("A valid name is required.");
        this.user.focus();
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
      this.password.value = hashPassword(this.email.value, this.password.value);
      this.confirm.value = this.password.value;
      return;
    };

    var form = document.getElementById("register_form");
    form.addEventListener("submit", checkForm, true);
    document.getElementById("password").value = "";
    document.getElementById("confirm").value = "";

    // HTML5 form validation

    var supports_input_validity = function()
    {
      var i = document.createElement("input");
      return "setCustomValidity" in i;
    }

    if(supports_input_validity()) {
      var emailInput = document.getElementById("email");
      emailInput.setCustomValidity(emailInput.title);

      var passwordInput = document.getElementById("password");
      passwordInput.setCustomValidity(passwordInput.title);

      var confirmInput = document.getElementById("confirm");

      // input key handlers

      emailInput.addEventListener("keyup", function(e) {
        emailInput.setCustomValidity(this.validity.patternMismatch ? emailInput.title : "");
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
