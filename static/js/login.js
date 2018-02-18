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

    addHTML5FormValidation('login_form')

  }, false);
