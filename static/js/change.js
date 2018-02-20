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
      if(this.password.value != "" && this.password.value == this.confirm.value) {
        if(!checkPassword(this.password.value)) {
          alert("The password you have entered is not valid.");
          this.password.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("The new and confirmed passwords do not match.");
        this.password.focus();
        e.preventDefault();
        return;
      }
      this.oldpassword.value = hashPassword(this.email.value, this.oldpassword.value);
      this.password.value = hashPassword(this.email.value, this.password.value);
      this.confirm.value = this.password.value;
      return;
    };

    // Add HTML5 form validation to check user input as they fill out and before submit
    addHTML5FormValidation('change_form')

    // Run checkForm function on submit, which does hashPassword and additional checks
    const form = document.getElementById('change_form');
    form.addEventListener("submit", checkForm, true);

  }, false);
