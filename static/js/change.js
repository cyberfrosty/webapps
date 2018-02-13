/**
 * Password change form validation code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017-2018 Alan Frost
 */

  document.addEventListener("DOMContentLoaded", function() {
    var checkForm = function(e)
    {
      if(this.newpassword.value != "" && this.newpassword.value == this.confirm.value) {
        if(!checkPassword(this.newpassword.value)) {
          alert("The password you have entered is not valid.");
          this.newpassword.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("The new and confirmed passwords do not match.");
        this.newpassword.focus();
        e.preventDefault();
        return;
      }
      this.password.value = hashPassword(this.email.value, this.password.value);
      this.newpassword.value = hashPassword(this.email.value, this.newpassword.value);
      this.confirm.value = this.newpassword.value;
      return;
    };

    var change_form = document.getElementById("change_form");
    change_form.addEventListener("submit", checkForm, true);

    // HTML5 form validation

    var supports_input_validity = function()
    {
      var i = document.createElement("input");
      return "setCustomValidity" in i;
    }

    if(supports_input_validity()) {
      var passwordInput = document.getElementById("password");
      var newpasswordInput = document.getElementById("newpassword");
      var confirmInput = document.getElementById("confirm");
      newpasswordInput.setCustomValidity(newpasswordInput.title);

      // input key handlers
      newpasswordInput.addEventListener("keyup", function(e) {
        this.setCustomValidity(this.validity.patternMismatch ? newpasswordInput.title : "");
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

      passwordInput.addEventListener("keyup", function(e) {
        this.setCustomValidity(this.validity.patternMismatch ? passwordInput.title : "");
      }, false);

    }

  }, false);
