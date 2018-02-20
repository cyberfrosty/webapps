/**
 * Login form validation code
 *
 * @author Alan Frost
 *
 * Copyright (c) 2017 Alan Frost
 */

  document.addEventListener("DOMContentLoaded", function() {
    var checkForm = function(e)
    {
      if(this.password.value != "") {
        if(!checkPassword(this.password.value)) {
          alert("The password you have entered is not valid.");
          this.password.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("A password is required.");
        this.password.focus();
        e.preventDefault();
        return;
      }
      this.password.value = hashPassword(this.email.value, this.password.value);
      return;
    };

    // Add HTML5 form validation to check user input as they fill out and before submit
    addHTML5FormValidation('login_form')

    // Run checkForm function on submit, which does hashPassword and additional checks
    const form = document.getElementById('login_form');
    form.addEventListener("submit", checkForm, true);

  }, false);
