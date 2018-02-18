/**
 * User account confirmation form validation code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017-2018 Alan Frost
 */

  document.addEventListener("DOMContentLoaded", function() {
    var checkForm = function(e)
    {
      if(!checkEmail(this.email.value)) {
        alert("Error: The email address you have entered is not valid.");
        this.email.focus();
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

    var form = document.getElementById("confirm_form");
    form.addEventListener("submit", checkForm, true);
    document.getElementById("password").value = "";
    document.getElementById("confirm").value = "";

    addHTML5FormValidation('confirm_form')

  }, false);
