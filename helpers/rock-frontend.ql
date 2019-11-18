import python

from Value os, CallNode call
where 
 os.getName() = "shell" and os.getACall() = call
select call, "Potential OS Command Injection"

