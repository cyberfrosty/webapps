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
          alert("The email you have entered is not valid.");
          this.email.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("A valid email is required.");
        this.email.focus();
        e.preventDefault();
        return;
      }
      if(this.name.value != "") {
        if(!checkName(this.name.value)) {
          alert("Names must be 4-32 characters in length with no numbers or special characters.");
          this.name.focus();
          e.preventDefault();
          return;
        }
      } else {
        alert("A valid name is required.");
        this.name.focus();
        e.preventDefault();
        return;
      }
      return;
    };

    var form = document.getElementById("invite_form");
    form.addEventListener("submit", checkForm, true);

  }, false);
