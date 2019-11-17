import python

string message() {
    result = "Potential OS Command Injection."
}

predicate os_function_call(Call c) {
exists(GlobalVariable os | os = ((Name)c.getFunc()).getVariable() and os.getId() = "shell")
}

from AstNode os
where os_function_call(os)
select os, message()
