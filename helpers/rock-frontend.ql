
import python
 
string message() {
    result = "Potential OS Command Injection." and major_version() = 2
    or
    result = "Potential OS Command Injection." and major_version() = 3
}
 
predicate os_function_call(Call c) {
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "popen") or
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "Popen") or
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "run") or
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "call") or
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "shell") or
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "exec") or
    exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "system")
}
 
from AstNode os
where os_function_call(os)
select os, message()
