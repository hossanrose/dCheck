function ValidateEmail(inputText)  
{  
var mailformat = /\w+([\.-]?\w+)*(\.\w{2,4})+$/;  
if(inputText.value.match(mailformat))  
{  
document.form.domain.focus();  
return true;  
}  
else  
{  
alert("You have entered an incorrect domain!");  
document.form.domain.focus();  
return false;  
}  
} 
